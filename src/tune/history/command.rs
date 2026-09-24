use super::*;
use clap::{Arg, ArgAction, Command};
use std::io::Write;

pub(crate) fn command_for_help() -> Command {
    crate::help::configure(
        Command::new("syq tuning-cache")
            .about("Inspect and clear local transfer tuning history")
            .subcommand_required(true)
            .subcommand(
                Command::new("list").about("List recent transfers").arg(
                    Arg::new("limit")
                        .long("limit")
                        .default_value("50")
                        .value_parser(clap::value_parser!(u32)),
                ),
            )
            .subcommand(
                Command::new("show")
                    .about("Show a transfer's measurements and decisions")
                    .arg(
                        Arg::new("id")
                            .required(true)
                            .value_parser(clap::value_parser!(i64)),
                    )
                    .arg(
                        Arg::new("html")
                            .long("html")
                            .action(ArgAction::SetTrue)
                            .help("Write a standalone interactive timeline to stdout"),
                    ),
            )
            .subcommand(
                Command::new("export")
                    .about("Export history as NDJSON; omit ID for every transfer")
                    .arg(Arg::new("id").value_parser(clap::value_parser!(i64))),
            )
            .subcommand(
                Command::new("clear").about("Delete recorded history and filesystem startup hints"),
            ),
    )
}

pub(crate) fn run(args: &[std::ffi::OsString]) -> Result<i32> {
    let matches = match command_for_help().try_get_matches_from(
        std::iter::once(std::ffi::OsString::from("syq tuning-cache")).chain(args.iter().cloned()),
    ) {
        Ok(matches) => matches,
        Err(error) => {
            let code = error.exit_code();
            error.print()?;
            return Ok(code);
        }
    };
    crate::fsops::reserve_startup_descriptors();
    let path = path().context("tuning persistence is disabled")?;
    if !path.exists() {
        if matches.subcommand_name() == Some("clear") || matches.subcommand_name() == Some("list") {
            return Ok(0);
        }
        bail!("no tuning history has been recorded");
    }
    let db = open(&path)?;
    let mut output = std::io::stdout().lock();
    match matches.subcommand() {
        Some(("list", args)) => {
            writeln!(
                output,
                "ID\tDATE\tSTATUS\tSECONDS\tFILES\tBYTES\tWORKERS\tEVENTS"
            )?;
            let mut statement=db.prepare("SELECT id,day,status,summary,CASE WHEN eligible=1 THEN workers END,(SELECT count(*) FROM events WHERE run=runs.id) FROM runs ORDER BY id DESC LIMIT ?1")?;
            let rows =
                statement.query_map([args.get_one::<u32>("limit").copied().unwrap()], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<u32>>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                })?;
            for row in rows {
                let (id, day, status, summary, workers, events) = row?;
                let summary: Value = summary
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Value::Null);
                let seconds = summary["elapsed_ms"]
                    .as_u64()
                    .map(|v| format!("{:.3}", v as f64 / 1000.0))
                    .unwrap_or_else(|| "?".into());
                writeln!(
                    output,
                    "{id}\t{}\t{status}\t{seconds}\t{}\t{}\t{}\t{events}",
                    date(day),
                    summary["files"]
                        .as_u64()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into()),
                    summary["bytes"]
                        .as_u64()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into()),
                    workers.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
                )?;
            }
        }
        Some(("show", args)) => {
            let id = *args.get_one::<i64>("id").unwrap();
            let record = read_run(&db, id)?;
            let events = read_events(&db, id)?;
            if args.get_flag("html") {
                let data = serde_json::to_string(&json!({"run":record,"events":events}))?
                    .replace('<', "\\u003c")
                    .replace('&', "\\u0026");
                output.write_all(
                    include_str!("viewer.html")
                        .replace("__HISTORY_DATA__", &data)
                        .as_bytes(),
                )?;
            } else {
                writeln!(output, "{}", serde_json::to_string_pretty(&record)?)?;
                for event in events {
                    writeln!(
                        output,
                        "{:>10.3}s  {:<18} {}",
                        event["elapsed_us"].as_u64().unwrap_or(0) as f64 / 1e6,
                        event["kind"].as_str().unwrap_or("?"),
                        event["data"]
                    )?;
                }
            }
        }
        Some(("export", args)) => {
            let ids = if let Some(id) = args.get_one::<i64>("id") {
                vec![*id]
            } else {
                db.prepare("SELECT id FROM runs ORDER BY id")?
                    .query_map([], |r| r.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            for id in ids {
                writeln!(
                    output,
                    "{}",
                    json!({"type":"transfer","schema":SCHEMA,"run":read_run(&db,id)?})
                )?;
                let mut statement =
                    db.prepare("SELECT data FROM events WHERE run=?1 ORDER BY sequence")?;
                for row in statement.query_map([id], |r| r.get::<_, String>(0))? {
                    writeln!(
                        output,
                        "{}",
                        json!({"type":"event","run":id,"event":serde_json::from_str::<Value>(&row?)?})
                    )?;
                }
            }
        }
        Some(("clear", _)) => {
            db.execute("DELETE FROM runs", [])?;
            db.execute_batch("PRAGMA incremental_vacuum;")?;
            writeln!(
                output,
                "Cleared tuning history. The legacy connection-count cache is unchanged."
            )?;
        }
        _ => unreachable!(),
    }
    Ok(0)
}

fn date(day: i64) -> String {
    let seconds = (day.saturating_mul(86400)) as libc::time_t;
    let mut date = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: gmtime_r initializes date on success and keeps no pointers.
    if unsafe { libc::gmtime_r(&seconds, date.as_mut_ptr()) }.is_null() {
        return "unknown".into();
    }
    let date = unsafe { date.assume_init() };
    format!(
        "{:04}-{:02}-{:02}",
        date.tm_year + 1900,
        date.tm_mon + 1,
        date.tm_mday
    )
}

pub(super) fn read_run(db: &Connection, id: i64) -> Result<Value> {
    let row = db
        .query_row(
            "SELECT day,build,context,status,workers,summary,lost,eligible FROM runs WHERE id=?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<u32>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)? == 1,
                ))
            },
        )
        .optional()?
        .context(format!("no transfer {id} in tuning history"))?;
    let (day, build, context, status, workers, summary, lost, eligible) = row;
    Ok(json!({"id":id, "date":date(day), "build":build,
        "context":serde_json::from_str::<Value>(&context)?, "status":status,
        "selected_workers":workers, "recommendation_eligible":eligible,
        "summary":summary.map(|s|serde_json::from_str::<Value>(&s)).transpose()?,
        "lost_events":lost}))
}

pub(super) fn read_events(db: &Connection, id: i64) -> Result<Vec<Value>> {
    let mut statement = db.prepare("SELECT data FROM events WHERE run=?1 ORDER BY sequence")?;
    let result = statement
        .query_map([id], |r| r.get::<_, String>(0))?
        .map(|row| Ok(serde_json::from_str(&row?)?))
        .collect();
    result
}
