//! `syq find` and `syq ls` on S3.
//!
//! Roots are found with listings alone, so that `s3:ListBucket` suffices
//! unless an expression or `--include` asks for metadata that only a HEAD
//! request returns. A listing to a depth reads directory by directory with
//! the delimiter `/` (`levels`); without one it lists every key under the
//! root, divided among requests as copies do, and reports the directories
//! that the keys imply. A `path glob` or `path =` condition joined to the
//! rest of `--where` with `and` narrows those requests; the whole expression
//! is still evaluated on every entry.
//!
//! Records stream while the listing runs. Objects that need a HEAD request
//! queue for a bounded number of requests at a time; listing pauses while
//! the queue is full.
use super::{client, listing, local};
use crate::cli::Args;
use crate::expression::{Facts, PathToken, Policy};
use crate::native_find::{Options, Printer, Record};
use anyhow::{bail, Context, Result};
use futures_util::{StreamExt, TryStreamExt};
use listing::engine::{self, levels, Entry, Page, Store};
use listing::pattern::Pattern;
use std::{
    cell::{Cell, RefCell},
    collections::{HashSet, VecDeque},
    io::Write,
    sync::{atomic::AtomicUsize, Arc},
    task::{Poll, Waker},
};

/// HEAD requests in flight at once.
const HEADS: usize = 32;
/// Objects waiting for a HEAD request before listing pauses.
const QUEUED: usize = 4096;
/// Delimiter requests a filtered listing may spend looking past a first page
/// in which every object is in an ignored directory, as copies do.
const LOOKAHEAD_PROBES: usize = 4;

/// A search root: an object listed by itself, or a directory prefix, empty
/// or ending with `/`. `display` is how output shows it.
enum Root {
    Object { entry: Entry, display: Vec<u8> },
    Directory { prefix: String, display: Vec<u8> },
}

pub(crate) fn run(args: &Args, options: &Options, out: &mut impl Write) -> Result<()> {
    let mut storage = args.s3.clone().context("S3 listing options")?;
    options.check_fields(true)?;
    if options.depth == Some(0) {
        bail!("--depth must be at least 1");
    }
    let base = local::key_path(crate::native_find::root_display(
        options
            .root
            .as_deref()
            .or(options.cwd.as_deref())
            .unwrap_or(b"."),
    ))?;
    let concurrency = args
        .tuning_options
        .and_then(|tuning| tuning.s3_requests)
        .unwrap_or(client::LISTING_REQUESTS)
        .min(256);
    let mut policy = Policy::compile_listing(options.where_expression.as_deref())?;
    policy.now = options.expression_now;
    let directories = policy.may_select_s3_directory();
    let pushdown = policy.s3_path_pushdown();
    let ignore = crate::scan::build_ignore(&options.ignore)?;
    // The listing gives every field but stored metadata, and a kind other
    // than "file" for an object, which only an explicit --include asks for.
    let heads = options
        .include
        .as_ref()
        .is_some_and(|fields| fields.iter().any(|field| field.needs_s3_head()));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (client, note) =
                client::connect(&mut storage, Arc::default(), Arc::default()).await?;
            if let Some(note) = note {
                crate::output::diagnostic!("syq find: {note}");
            }
            let store = listing::S3 {
                client: client.clone(),
                bucket: &storage.bucket,
                divides: listing::lists_in_byte_order(storage.endpoint.as_deref(), &storage.bucket),
            };
            // Find every root before writing anything, so that a missing
            // one fails before any output.
            let mut roots = Vec::new();
            if options.paths.is_empty() {
                roots.push(Root::Directory {
                    prefix: directory_prefix(&base),
                    display: Vec::new(),
                });
            }
            for path in &options.paths {
                roots.push(resolve(&store, &base, path).await?);
            }
            let finder = Finder {
                client: &client,
                bucket: &storage.bucket,
                store: &store,
                printer: Printer::new(options, true),
                policy,
                directories,
                pushdown,
                ignore,
                depth: options.depth,
                concurrency,
                heads,
                out: RefCell::new(out),
            };
            for root in roots {
                finder.list(root).await?;
            }
            finder.out.borrow_mut().flush()?;
            Ok(())
        })
}

fn directory_prefix(key: &str) -> String {
    if key.is_empty() {
        String::new()
    } else {
        format!("{key}/")
    }
}

/// The root `path` names beneath `base`, found with listings only: a path
/// ending with `/` names a directory; another names the object of that key
/// if there is one, else the directory.
///
/// A store that lists only prefixes ending with `/` finds the object in a
/// listing of the directory that holds it, which can take many requests, so
/// there the directory is looked for first and is chosen if it holds keys.
async fn resolve(store: &listing::S3<'_>, base: &str, path: &[u8]) -> Result<Root> {
    let display = crate::native_find::root_display(path).to_vec();
    if display.is_empty() {
        return Ok(Root::Directory {
            prefix: directory_prefix(base),
            display,
        });
    }
    let key = local::join(base, &local::key_path(&display)?);
    let shown = String::from_utf8_lossy(path);
    let prefix = format!("{key}/");
    let object = !path.ends_with(b"/");
    let mut refused = None;
    if object && !store.slash_only() {
        match levels::exact(store, &key).await {
            Ok((Some(entry), _)) => return Ok(Root::Object { entry, display }),
            Ok((None, true)) => return Ok(Root::Directory { prefix, display }),
            Ok((None, false)) => {}
            // A policy that lets you list only the prefix `key/` refuses
            // a listing of `key`.
            Err(error) if denied(&error) => refused = Some(error),
            Err(error) => return Err(error),
        }
    }
    if holds_keys(store, &prefix).await? {
        return Ok(Root::Directory { prefix, display });
    }
    if object && store.slash_only() {
        if let Some(entry) = engine::exact_in_directory(store, &key).await? {
            return Ok(Root::Object { entry, display });
        }
    }
    if let Some(error) = refused {
        return Err(error.context(format!(
            "cannot list {shown}: no objects under {prefix:?}, and listing {key:?} to look for the object was refused"
        )));
    }
    bail!("cannot list {shown}: no S3 object {key:?}, and no objects under {prefix:?}");
}

/// Whether any key starts with `prefix`, which ends with `/`.
async fn holds_keys(store: &listing::S3<'_>, prefix: &str) -> Result<bool> {
    let mut page = store.first_key(prefix).await?;
    while page.entries.is_empty() {
        let Some(token) = page.next.take() else {
            return Ok(false);
        };
        page = engine::read(store, prefix, false, Some(&token)).await?;
    }
    Ok(true)
}

/// Whether a request failed because a policy refused it.
fn denied(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<client::RequestFailure>()
        .is_some_and(client::RequestFailure::denied)
}

struct Finder<'a, W> {
    client: &'a aws_sdk_s3::Client,
    bucket: &'a str,
    store: &'a listing::S3<'a>,
    printer: Printer,
    policy: Policy,
    directories: bool,
    pushdown: Vec<Vec<PathToken>>,
    ignore: Option<ignore::gitignore::Gitignore>,
    depth: Option<u32>,
    concurrency: usize,
    /// Whether every object needs a HEAD request for its output fields.
    heads: bool,
    out: RefCell<&'a mut W>,
}

/// What narrowing a root's listing to the pushed-down path patterns gives.
enum Narrowed {
    /// List keys matching this pattern.
    Pattern(Pattern),
    /// Nothing beneath the root can match.
    Nothing,
    /// The patterns do not narrow the listing.
    Everything,
}

impl<W: Write> Finder<'_, W> {
    async fn list(&self, root: Root) -> Result<()> {
        let (prefix, display) = match root {
            Root::Object { entry, display } => {
                if crate::scan::selected_file_is_ignored(self.ignore.as_ref(), &display) {
                    return Ok(());
                }
                let state = State::new(self, String::new(), display.clone());
                let path = display.clone();
                return state
                    .run(async {
                        state.object(entry, path);
                        state.check()
                    })
                    .await;
            }
            Root::Directory { prefix, display } => (prefix, display),
        };
        let narrowed = self.narrow(&prefix, &display)?;
        if matches!(narrowed, Narrowed::Nothing) {
            return Ok(());
        }
        let pattern = match narrowed {
            Narrowed::Pattern(pattern) => Some(pattern),
            _ => None,
        };
        if let Some(depth) = self.depth {
            let state = State::new(self, prefix.clone(), display);
            let ignore = self.ignore.as_ref();
            let descend = |child: &str| {
                let relative = &child[prefix.len()..child.len() - 1];
                !ignore.is_some_and(|ignore| {
                    crate::scan::path_is_ignored(ignore, relative.as_bytes(), true)
                }) && pattern
                    .as_ref()
                    .is_none_or(|pattern| pattern.may_match_under(child))
            };
            let paced = state.paced(&prefix);
            return state
                .run(levels::walk(
                    &paced,
                    &prefix,
                    depth,
                    self.concurrency,
                    &descend,
                    |found| {
                        match found {
                            levels::Found::Object(entry) => state.key(entry, false),
                            levels::Found::Directory(prefix) => {
                                if self.directories {
                                    state.directory(&prefix[state.prefix.len()..prefix.len() - 1]);
                                }
                            }
                        }
                        state.check()
                    },
                ))
                .await;
        }
        let mut pattern = pattern;
        let mut concurrency = self.concurrency;
        loop {
            let state = State::new(self, prefix.clone(), display.clone());
            let paced = state.paced(&prefix);
            let result = match &pattern {
                Some(pattern) => {
                    state
                        .run(engine::enumerate(&paced, pattern, concurrency, |entry| {
                            state.key(entry, true);
                            state.check()
                        }))
                        .await
                }
                None => {
                    let ignore = self.ignore.as_ref();
                    let subtree = |key: &str, directory: bool| {
                        ignored_boundary(ignore?, &prefix, key, directory)
                    };
                    let prune = self.ignore.as_ref().map(|_| engine::Prune {
                        subtree: &subtree,
                        probes: AtomicUsize::new(if concurrency == 1 {
                            0
                        } else {
                            LOOKAHEAD_PROBES
                        }),
                    });
                    state
                        .run(async {
                            let pruned = engine::enumerate_prefix(
                                &paced,
                                &prefix,
                                concurrency,
                                prune.as_ref(),
                                |entry| {
                                    state.key(entry, true);
                                    state.check()
                                },
                            )
                            .await?;
                            if self.directories {
                                // A pruned directory was not listed, but its
                                // parents exist.
                                for directory in pruned {
                                    state.parents(&directory[prefix.len()..]);
                                }
                            }
                            state.check()
                        })
                        .await
                }
            };
            let Err(error) = result else {
                return Ok(());
            };
            // Divided and narrowed listings fail where a policy allows
            // listing only the prefix itself, and divided ones where keys
            // arrive out of order; a listing of the prefix one page after
            // another without lookahead probes does not. Start over if nothing
            // was printed yet.
            let denied = denied(&error)
                && (state.discovery_denied.get()
                    || error.downcast_ref::<engine::PartFailed>().is_some());
            if (pattern.is_none() && concurrency == 1)
                || !(denied || error.is::<engine::Unordered>())
            {
                return Err(error);
            }
            if state.printed.get() {
                if concurrency > 1 {
                    return Err(error.context(
                        "to list the prefix one page after another, as a policy that lets you list only the prefix itself requires, rerun with --performance-tuning s3-requests=1",
                    ));
                }
                return Err(error);
            }
            pattern = None;
            concurrency = 1;
        }
    }

    /// Narrow the listing of the directory `prefix`, shown as `display`, to
    /// the most selective pushed-down pattern.
    fn narrow(&self, prefix: &str, display: &[u8]) -> Result<Narrowed> {
        let mut best: Option<(Pattern, (usize, usize))> = None;
        for tokens in &self.pushdown {
            // Emitted paths are `display/relative`; keys are
            // `prefix/relative`.
            let mut rest = tokens.as_slice();
            if !display.is_empty() {
                let Ok(display) = std::str::from_utf8(display) else {
                    continue;
                };
                let mut fits = true;
                for c in display.chars().chain(['/']) {
                    match rest.split_first() {
                        Some((PathToken::Literal(literal), tail)) if *literal == c => rest = tail,
                        Some((PathToken::Literal(_), _)) | None => return Ok(Narrowed::Nothing),
                        Some(_) => {
                            fits = false;
                            break;
                        }
                    }
                }
                if !fits {
                    continue;
                }
            }
            if rest.is_empty() {
                return Ok(Narrowed::Nothing);
            }
            // When the expression may select directories, broaden the pattern
            // because a directory is reported from keys beneath it and a
            // marker key ends with '/'.
            let mut tokens = rest.to_vec();
            if self.directories {
                tokens.push(PathToken::Recursive);
            }
            let pattern = Pattern::from_tokens(prefix, &tokens)?;
            let narrowing = pattern
                .components
                .iter()
                .position(|part| part.recursive())
                .map(|at| (at, pattern.components[at].literal_prefix().len()))
                .unwrap_or((pattern.components.len(), 0));
            if best.as_ref().is_none_or(|(_, score)| narrowing > *score) {
                best = Some((pattern, narrowing));
            }
        }
        let floor = (prefix.matches('/').count(), 0);
        Ok(match best {
            Some((pattern, score)) if score > floor => Narrowed::Pattern(pattern),
            _ => Narrowed::Everything,
        })
    }

    fn ignored(&self, relative: &str, directory: bool) -> bool {
        self.ignore.as_ref().is_some_and(|ignore| {
            crate::scan::path_is_ignored(ignore, relative.as_bytes(), directory)
        })
    }
}

/// The byte length of the topmost ignored directory holding `key`, or of
/// `key` when it names an ignored directory.
fn ignored_boundary(
    ignore: &ignore::gitignore::Gitignore,
    prefix: &str,
    key: &str,
    directory: bool,
) -> Option<usize> {
    let relative = key.strip_prefix(prefix)?;
    let relative = if directory {
        relative.trim_end_matches('/')
    } else {
        relative
    };
    for (at, _) in relative.match_indices('/') {
        if ignore.matched(&relative[..at], true).is_ignore() {
            return Some(prefix.len() + at);
        }
    }
    (directory && !relative.is_empty() && ignore.matched(relative, true).is_ignore())
        .then_some(prefix.len() + relative.len())
}

/// An object waiting for its HEAD request.
struct Queued {
    entry: Entry,
    path: Vec<u8>,
    /// Whether `--where` still has to decide on it.
    filter: bool,
}

/// One root's listing: what it printed and queued, and the directories it
/// reported.
struct State<'a, 'f, W> {
    finder: &'a Finder<'f, W>,
    prefix: String,
    display: Vec<u8>,
    queue: RefCell<VecDeque<Queued>>,
    waker: RefCell<Option<Waker>>,
    room: tokio::sync::Notify,
    done: Cell<bool>,
    printed: Cell<bool>,
    discovery_denied: Cell<bool>,
    failed: RefCell<Option<anyhow::Error>>,
    directories: RefCell<HashSet<String>>,
}

impl<'a, 'f, W: Write> State<'a, 'f, W> {
    fn new(finder: &'a Finder<'f, W>, prefix: String, display: Vec<u8>) -> Self {
        Self {
            finder,
            prefix,
            display,
            queue: RefCell::default(),
            waker: RefCell::default(),
            room: tokio::sync::Notify::new(),
            done: Cell::new(false),
            printed: Cell::new(false),
            discovery_denied: Cell::new(false),
            failed: RefCell::default(),
            directories: RefCell::default(),
        }
    }

    fn paced<'s>(&'s self, root: &'s str) -> Paced<'s, 'a, 'f, W> {
        Paced { state: self, root }
    }

    /// Run `producer`, which reports entries to this state, beside the HEAD
    /// requests its objects need.
    async fn run(&self, producer: impl std::future::Future<Output = Result<()>>) -> Result<()> {
        let producer = async {
            let result = producer.await;
            self.done.set(true);
            if let Some(waker) = self.waker.borrow_mut().take() {
                waker.wake();
            }
            result?;
            self.check()
        };
        tokio::try_join!(producer, self.heads())?;
        Ok(())
    }

    fn path(&self, relative: &str) -> Vec<u8> {
        crate::native_find::join(&self.display, relative.as_bytes())
    }

    /// Report a listed key. With `parents`, also report the directories
    /// above it beneath the root that were not reported yet.
    fn key(&self, entry: Entry, parents: bool) {
        let Some(relative) = entry.key.strip_prefix(&self.prefix) else {
            return;
        };
        if relative.is_empty() {
            // The root's own marker.
            return;
        }
        let relative = relative.to_owned();
        if parents && self.finder.directories {
            self.parents(&relative);
        }
        if client::is_directory_marker(&entry.key, entry.size) {
            if !parents && self.finder.directories {
                self.directory(relative.trim_end_matches('/'));
            }
            return;
        }
        if self.finder.ignored(&relative, false) {
            return;
        }
        let path = self.path(&relative);
        self.object(entry, path);
    }

    /// Report the directories that hold `relative`, from the top down, and
    /// the directory itself if it ends with `/`.
    fn parents(&self, relative: &str) {
        let mut new = Vec::new();
        {
            let mut known = self.directories.borrow_mut();
            for (at, _) in relative
                .match_indices('/')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                let directory = &relative[..at];
                if !known.insert(directory.to_owned()) {
                    break;
                }
                new.push(at);
            }
        }
        for at in new.into_iter().rev() {
            self.directory(&relative[..at]);
        }
    }

    fn directory(&self, relative: &str) {
        if relative.is_empty() || self.finder.ignored(relative, true) {
            return;
        }
        let path = self.path(relative);
        let result = (|| {
            if self
                .finder
                .policy
                .selects_listing_known(Facts::S3Directory, &path)?
                != Some(true)
            {
                return Ok(());
            }
            self.print(&Record {
                path: &path,
                kind: "dir",
                ..Record::default()
            })
        })();
        self.keep(result);
    }

    fn object(&self, entry: Entry, path: Vec<u8>) {
        let result = (|| {
            let selected = self.finder.policy.selects_listing_known(
                Facts::S3Listing {
                    size: entry.size,
                    directory_marker: false,
                    last_modified: entry.last_modified,
                },
                &path,
            )?;
            if selected == Some(false) {
                return Ok(());
            }
            if selected.is_some() && !self.finder.heads {
                return self.print_object(&path, &entry, None);
            }
            self.queue.borrow_mut().push_back(Queued {
                entry,
                path,
                filter: selected.is_none(),
            });
            if let Some(waker) = self.waker.borrow_mut().take() {
                waker.wake();
            }
            Ok(())
        })();
        self.keep(result);
    }

    /// The error a report kept, which ends the listing.
    fn check(&self) -> Result<()> {
        match self.failed.borrow_mut().take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Keep the first error of a report, which ends the listing.
    fn keep(&self, result: Result<()>) {
        if let Err(error) = result {
            self.failed.borrow_mut().get_or_insert(error);
        }
    }

    fn print(&self, record: &Record) -> Result<()> {
        self.finder
            .printer
            .write(&mut **self.finder.out.borrow_mut(), record)?;
        self.printed.set(true);
        Ok(())
    }

    fn print_object(
        &self,
        path: &[u8],
        entry: &Entry,
        object: Option<&client::Object>,
    ) -> Result<()> {
        let metadata = object.and_then(|object| object.metadata.as_ref());
        let kind = object.map_or("file", |object| object.kind().as_str());
        self.print(&Record {
            path,
            kind,
            size: (kind == "file").then_some(entry.size),
            mtime: metadata.map(|metadata| metadata.mtime),
            s3_last_modified: entry.last_modified.map(|(seconds, _)| seconds),
            etag: entry.etag.as_deref(),
            mode: metadata.map(|metadata| metadata.mode & 0o7777),
            uid: metadata.map(|metadata| metadata.uid),
            gid: metadata.map(|metadata| metadata.gid),
            ctime: None,
            link_target: None,
        })
    }

    /// Wait until the HEAD queue has room.
    async fn room(&self) {
        loop {
            let notified = self.room.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.queue.borrow().len() < QUEUED {
                return;
            }
            notified.await;
        }
    }

    /// Send the HEAD requests that queued objects need, and print them.
    async fn heads(&self) -> Result<()> {
        let queued = futures_util::stream::poll_fn(|context| {
            if let Some(queued) = self.queue.borrow_mut().pop_front() {
                self.room.notify_waiters();
                return Poll::Ready(Some(queued));
            }
            if self.done.get() {
                return Poll::Ready(None);
            }
            *self.waker.borrow_mut() = Some(context.waker().clone());
            Poll::Pending
        });
        let mut heads = queued
            .map(|queued| async move {
                let object =
                    client::head(self.finder.client, self.finder.bucket, &queued.entry.key).await?;
                Ok::<_, anyhow::Error>((queued, object))
            })
            .buffered(HEADS);
        while let Some((queued, object)) = heads.try_next().await? {
            // Removed since it was listed.
            let Some(object) = object else {
                continue;
            };
            let mut file = object.expression_file();
            // Keep the listing's Last-Modified (millisecond precision, or
            // absent) so HEAD filtering sees the same value as LIST filtering.
            file.s3_last_modified = queued.entry.last_modified;
            if queued.filter && !self.finder.policy.selects_listing(&file, &queued.path)? {
                continue;
            }
            self.print_object(&queued.path, &queued.entry, Some(&object))?;
        }
        Ok(())
    }
}

/// The store a root's listing reads through: it waits while the HEAD queue
/// is full, sends what was printed before each request, and notes refused
/// requests that an exact-prefix policy may deny.
struct Paced<'s, 'a, 'f, W> {
    state: &'s State<'a, 'f, W>,
    root: &'s str,
}

impl<W: Write> Store for Paced<'_, '_, '_, W> {
    fn ordered(&self) -> bool {
        self.state.finder.store.ordered()
    }

    fn slash_only(&self) -> bool {
        self.state.finder.store.slash_only()
    }

    fn divides(&self) -> bool {
        self.state.finder.store.divides()
    }

    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        self.state.room().await;
        self.state.finder.out.borrow_mut().flush()?;
        self.state.check()?;
        self.state
            .finder
            .store
            .page(prefix, delimiter, token, start_after)
            .await
            .inspect_err(|error| {
                let denied = error
                    .downcast_ref::<client::RequestFailure>()
                    .is_some_and(client::RequestFailure::denied);
                if denied && (delimiter || prefix != self.root) {
                    self.state.discovery_denied.set(true);
                }
            })
    }
}
