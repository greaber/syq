use super::*;

pub(super) struct DryRunMapping {
    pub(super) target: PathBytes,
    pub(super) semantics: &'static str,
}

/// A typed summary of final-state mutations found during a dry run. Type
/// replacements overlap the primary categories; all others are disjoint.
#[derive(Default)]
pub(super) struct DryRunChanges {
    pub(super) regular_files: u64,
    pub(super) directories: std::collections::HashSet<PathBytes>,
    /// Planned directory creations in plan order, traced only after the
    /// whole scan settles: a later explicit mapping entry can upgrade a
    /// synthesized ancestor, and an already-streamed trace could not gain
    /// its `src`.
    pub(super) directory_creates: Vec<(PathBytes, &'static str)>,
    pub(super) symlinks: u64,
    pub(super) specials: u64,
    pub(super) metadata_files: u64,
    pub(super) metadata_directories: std::collections::HashSet<PathBytes>,
    pub(super) type_replacements: u64,
}

impl DryRunChanges {
    pub(super) fn summary(&self) -> String {
        let mut categories = Vec::new();
        for (n, singular, plural) in [
            (self.regular_files, "regular file", "regular files"),
            (self.directories.len() as u64, "directory", "directories"),
            (self.symlinks, "symlink", "symlinks"),
            (self.specials, "special file", "special files"),
            (
                self.metadata_files + self.metadata_directories.len() as u64,
                "metadata-only entry",
                "metadata-only entries",
            ),
        ] {
            if n > 0 {
                categories.push(count_label(n, singular, plural));
            }
        }
        if categories.is_empty() {
            return "none".to_string();
        }
        if self.type_replacements > 0 {
            categories.push(format!(
                "{} among them",
                count_label(
                    self.type_replacements,
                    "type replacement",
                    "type replacements"
                )
            ));
        }
        categories.join("; ")
    }
}

#[derive(Clone, Copy)]
pub(super) enum DeletePlan {
    Disabled,
    Planned(u64),
    Skipped(&'static str),
}

pub(super) fn count_label(n: u64, singular: &str, plural: &str) -> String {
    format!("{} {}", commas(n), if n == 1 { singular } else { plural })
}

pub(super) fn deletion_summary(plan: DeletePlan, deleted: u64, max: Option<u64>) -> String {
    match plan {
        DeletePlan::Disabled => String::new(),
        DeletePlan::Planned(n) => {
            if let Some(limit) = max.filter(|limit| n > *limit) {
                format!(
                    ", {} planned for deletion (blocked by --max-delete {limit})",
                    commas(n)
                )
            } else {
                format!(", {} deleted", commas(deleted))
            }
        }
        DeletePlan::Skipped(reason) => format!(", deletions skipped ({reason})"),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn print_dry_run_summary(
    srcs: &[Location],
    dst: &Location,
    mappings: &[DryRunMapping],
    src_ep: &Endpoint,
    dst_ep: &Endpoint,
    args: &Args,
    opts: &Opts,
    progress: &Progress,
    deletes: DeletePlan,
    changes: &DryRunChanges,
    capacity: Option<FreshCapacityAssessment>,
) {
    crate::output::human_stdout!("syq: dry-run summary");
    for (source, mapping) in srcs.iter().zip(mappings) {
        crate::output::human_stdout!(
            "  mapping: {} -> {} ({})",
            display_plan_source(source, args),
            display_plan_target(dst, &mapping.target, args),
            mapping.semantics
        );
    }
    crate::output::human_stdout!("  changes: {}", changes.summary());

    match deletes {
        DeletePlan::Disabled => crate::output::human_stdout!("  deletions: disabled"),
        DeletePlan::Planned(n) => {
            if let Some(limit) = opts.max_delete.filter(|limit| n > *limit) {
                crate::output::human_stdout!(
                    "  deletions: {} planned; blocked by --max-delete {limit}",
                    count_label(n, "entry", "entries")
                );
            } else {
                crate::output::human_stdout!(
                    "  deletions: {} planned after a successful copy",
                    count_label(n, "entry", "entries")
                );
            }
        }
        DeletePlan::Skipped(reason) => {
            crate::output::human_stdout!("  deletions: skipped ({reason})")
        }
    }
    crate::output::human_stdout!(
        "  logical data: {} in {} needing content work (upper bound); {} in {} with unchanged content",
        human(progress.bytes_total.load(Relaxed)),
        count_label(progress.files_total.load(Relaxed), "file", "files"),
        human(progress.bytes_unchanged.load(Relaxed)),
        count_label(progress.files_unchanged.load(Relaxed), "file", "files")
    );
    if let Some(capacity) = capacity {
        let inode_detail = capacity.available_inodes.map_or_else(
            || {
                format!(
                    "{} destination objects; free inode count unavailable",
                    commas(capacity.objects)
                )
            },
            |available| {
                format!(
                    "{} destination objects; {} inodes available",
                    commas(capacity.objects),
                    commas(available)
                )
            },
        );
        if !capacity.check_bytes {
            crate::output::human_stdout!(
                "  capacity: {} logical data; sparse allocation size unknown; {} available; {inode_detail} ({})",
                human(capacity.logical_bytes),
                human(capacity.available_bytes),
                if capacity.inode_shortage() { "insufficient inodes" } else { "byte capacity not preflighted" }
            );
        } else {
            crate::output::human_stdout!(
                "  capacity: {} logical data required; {} available; {inode_detail} ({})",
                human(capacity.logical_bytes),
                human(capacity.available_bytes),
                if capacity.sufficient() {
                    "appears sufficient"
                } else {
                    "insufficient"
                }
            );
        }
    }

    let ignored = progress.paths_ignored.load(Relaxed);
    let other = progress.files_excluded.load(Relaxed);
    let mut exclusions = Vec::new();
    if ignored > 0 {
        exclusions.push(format!(
            "{} skipped by ignore rules",
            count_label(ignored, "path/subtree", "paths/subtrees")
        ));
    }
    if other > 0 {
        exclusions.push(count_label(other, "other entry", "other entries"));
    }
    crate::output::human_stdout!(
        "  exclusions: {}",
        if exclusions.is_empty() {
            if opts.ignore.is_empty() {
                "none".to_string()
            } else {
                "none matched (ignore rules active)".to_string()
            }
        } else {
            exclusions.join("; ")
        }
    );

    crate::output::human_stdout!("  route: {}", selected_route(src_ep, dst_ep, args));
}
