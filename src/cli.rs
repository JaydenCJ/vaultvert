//! Command-line interface: argument parsing and the four subcommands.
//!
//! Kept free of `std::process::exit` — `run` returns the exit code so the
//! whole CLI is unit-testable in-process. Exit codes: 0 success, 1 usage or
//! input error, 3 integrity verification failed (output written but the
//! round-trip check did not reproduce the source; the original is untouched).

use crate::detect::{self, Format};
use crate::json::Value;
use crate::merge;
use crate::model::{EntryKind, Vault};
use crate::report::Report;
use std::io::{Read as _, Write as _};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
vaultvert — convert and merge password-manager exports, losslessly

USAGE:
    vaultvert <COMMAND> [OPTIONS]

COMMANDS:
    convert <input> -o <output>      convert one export to another format
    merge <input>... -o <output>     merge exports, dedupe, keep every secret
    inspect <input>                  show format, counts, coverage and digest
    formats                          list supported formats

OPTIONS:
    -o, --output <path>    output file ('-' for stdout)
        --from <format>    force the input format (default: content sniffing)
        --to <format>      target format (default: from the output extension)
        --report <path>    also write the integrity report to a file
        --json             machine-readable output (inspect / --report file)
    -q, --quiet            do not print the report to stderr
    -h, --help             show this help
    -V, --version          show the version

Formats: bitwarden-json (rw), bitwarden-csv (r), 1pif (rw), keepass-xml (rw).
Everything runs offline; no vault byte ever leaves this process.
";

struct Args {
    positionals: Vec<String>,
    output: Option<String>,
    from: Option<String>,
    to: Option<String>,
    report: Option<String>,
    json: bool,
    quiet: bool,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        positionals: Vec::new(),
        output: None,
        from: None,
        to: None,
        report: None,
        json: false,
        quiet: false,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut take = |name: &str| -> Result<String, String> {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "-o" | "--output" => out.output = Some(take("--output")?),
            "--from" => out.from = Some(take("--from")?),
            "--to" => out.to = Some(take("--to")?),
            "--report" => out.report = Some(take("--report")?),
            "--json" => out.json = true,
            "-q" | "--quiet" => out.quiet = true,
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("unknown option '{other}'"))
            }
            other => out.positionals.push(other.to_string()),
        }
    }
    Ok(out)
}

pub fn run(argv: &[String]) -> i32 {
    let (command, rest) = match argv.first().map(String::as_str) {
        None | Some("-h") | Some("--help") | Some("help") => {
            print!("{HELP}");
            return 0;
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("vaultvert {VERSION}");
            return 0;
        }
        Some(cmd) => (cmd, &argv[1..]),
    };
    let args = match parse_args(rest) {
        Ok(a) => a,
        Err(e) => return usage_error(&e),
    };
    let result = match command {
        "convert" => cmd_convert(&args),
        "merge" => cmd_merge(&args),
        "inspect" => cmd_inspect(&args),
        "formats" => cmd_formats(),
        other => Err(format!("unknown command '{other}' (see --help)")),
    };
    match result {
        Ok(code) => code,
        Err(e) => usage_error(&e),
    }
}

fn usage_error(msg: &str) -> i32 {
    eprintln!("vaultvert: {msg}");
    1
}

fn read_input(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
    }
}

fn write_output(path: &str, data: &str) -> Result<(), String> {
    if path == "-" {
        std::io::stdout()
            .write_all(data.as_bytes())
            .map_err(|e| format!("stdout: {e}"))
    } else {
        std::fs::write(path, data).map_err(|e| format!("{path}: {e}"))
    }
}

fn load(path: &str, forced: &Option<String>) -> Result<(Vault, Format, Vec<String>), String> {
    let text = read_input(path)?;
    let format = match forced {
        Some(name) => Format::from_name(name)?,
        None => detect::sniff(&text, path)?,
    };
    let (vault, warnings) = format.read(&text)?;
    Ok((vault, format, warnings))
}

fn resolve_target(args: &Args, output: &str) -> Result<Format, String> {
    let format = match &args.to {
        Some(name) => Format::from_name(name)?,
        None => Format::from_extension(output).ok_or(
            "cannot infer the target format from the output name; pass --to \
             bitwarden-json|1pif|keepass-xml",
        )?,
    };
    Ok(format)
}

/// Write the vault in the target format, then re-parse the produced bytes
/// with the target's own reader and fill in the verification side of the
/// report. This is the "checked, not asserted" half of the lossless claim.
fn write_and_verify(
    vault: &Vault,
    target: Format,
    output: &str,
    rep: &mut Report,
) -> Result<(), String> {
    rep.target_name = output.to_string();
    rep.target_format = target.name().to_string();
    let text = target.write(vault, rep)?;
    let (reread, _) = target.read(&text)?;
    rep.target_entries = reread.entries.len();
    rep.target_digest = reread.digest();
    write_output(output, &text)?;
    Ok(())
}

fn emit_report(args: &Args, rep: &Report) -> Result<(), String> {
    if !args.quiet {
        eprint!("{}", rep.to_text());
    }
    if let Some(path) = &args.report {
        let body = if args.json {
            crate::json::to_pretty(&rep.to_json())
        } else {
            rep.to_text()
        };
        std::fs::write(path, body).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(())
}

fn cmd_convert(args: &Args) -> Result<i32, String> {
    let [input] = args.positionals.as_slice() else {
        return Err("convert takes exactly one input file (see --help)".into());
    };
    let output = args.output.as_deref().ok_or("convert needs -o <output>")?;
    let (vault, source, warnings) = load(input, &args.from)?;
    let target = resolve_target(args, output)?;

    let mut rep = Report::for_source(
        input,
        source.name(),
        vault.entries.len(),
        vault.digest(),
        warnings,
    );
    write_and_verify(&vault, target, output, &mut rep)?;
    emit_report(args, &rep)?;
    Ok(if rep.lossless() { 0 } else { 3 })
}

fn cmd_merge(args: &Args) -> Result<i32, String> {
    if args.positionals.len() < 2 {
        return Err("merge takes two or more input files (see --help)".into());
    }
    let output = args.output.as_deref().ok_or("merge needs -o <output>")?;
    let mut vaults = Vec::new();
    let mut warnings = Vec::new();
    let mut sources = Vec::new();
    for input in &args.positionals {
        let (vault, format, mut w) = load(input, &args.from)?;
        sources.push(format!("{input} ({})", format.name()));
        warnings.append(&mut w);
        vaults.push(vault);
    }
    let (merged, stats) = merge::merge(&vaults);
    let target = resolve_target(args, output)?;

    let mut rep = Report::for_source(
        &sources.join(" + "),
        "merged",
        merged.entries.len(),
        merged.digest(),
        warnings,
    );
    write_and_verify(&merged, target, output, &mut rep)?;
    if !args.quiet {
        use crate::report::count;
        eprintln!(
            "merge: {} inputs, {} in, {} merged ({} preserved), {} out",
            stats.inputs,
            count(stats.entries_in, "entry", "entries"),
            count(stats.duplicates_merged, "duplicate", "duplicates"),
            count(
                stats.password_conflicts,
                "password conflict",
                "password conflicts"
            ),
            count(stats.entries_out, "entry", "entries"),
        );
    }
    emit_report(args, &rep)?;
    Ok(if rep.lossless() { 0 } else { 3 })
}

fn cmd_inspect(args: &Args) -> Result<i32, String> {
    let [input] = args.positionals.as_slice() else {
        return Err("inspect takes exactly one input file (see --help)".into());
    };
    let (vault, format, warnings) = load(input, &args.from)?;
    let count = |k: EntryKind| vault.entries.iter().filter(|e| e.kind() == k).count();
    let with = |f: fn(&crate::model::Entry) -> bool| vault.entries.iter().filter(|e| f(e)).count();
    let folders: std::collections::BTreeSet<&str> = vault
        .entries
        .iter()
        .filter_map(|e| e.folder.as_deref())
        .collect();
    let custom_fields: usize = vault.entries.iter().map(|e| e.fields.len()).sum();

    if args.json {
        let doc = Value::obj(vec![
            ("file", Value::s(input)),
            ("format", Value::s(format.name())),
            ("entries", Value::Int(vault.entries.len() as i64)),
            (
                "kinds",
                Value::obj(vec![
                    ("login", Value::Int(count(EntryKind::Login) as i64)),
                    ("note", Value::Int(count(EntryKind::Note) as i64)),
                    ("card", Value::Int(count(EntryKind::Card) as i64)),
                    ("identity", Value::Int(count(EntryKind::Identity) as i64)),
                ]),
            ),
            ("folders", Value::Int(folders.len() as i64)),
            (
                "coverage",
                Value::obj(vec![
                    (
                        "username",
                        Value::Int(with(|e| e.username.is_some()) as i64),
                    ),
                    (
                        "password",
                        Value::Int(with(|e| e.password.is_some()) as i64),
                    ),
                    ("totp", Value::Int(with(|e| e.totp.is_some()) as i64)),
                    ("urls", Value::Int(with(|e| !e.urls.is_empty()) as i64)),
                    ("notes", Value::Int(with(|e| e.notes.is_some()) as i64)),
                ]),
            ),
            ("customFields", Value::Int(custom_fields as i64)),
            ("digest", Value::s(&vault.digest())),
            (
                "warnings",
                Value::Array(warnings.iter().map(|w| Value::s(w)).collect()),
            ),
        ]);
        print!("{}", crate::json::to_pretty(&doc));
        return Ok(0);
    }

    println!("file    : {input}");
    println!("format  : {} ({})", format.name(), format.describe());
    println!(
        "entries : {} (logins {}, notes {}, cards {}, identities {})",
        vault.entries.len(),
        count(EntryKind::Login),
        count(EntryKind::Note),
        count(EntryKind::Card),
        count(EntryKind::Identity)
    );
    println!("folders : {}", folders.len());
    println!(
        "coverage: username {}/{n}, password {}/{n}, totp {}/{n}, urls {}/{n}, notes {}/{n}, custom fields {}",
        with(|e| e.username.is_some()),
        with(|e| e.password.is_some()),
        with(|e| e.totp.is_some()),
        with(|e| !e.urls.is_empty()),
        with(|e| e.notes.is_some()),
        custom_fields,
        n = vault.entries.len()
    );
    println!("digest  : sha256:{}", vault.digest());
    for w in &warnings {
        println!("warning : {w}");
    }
    Ok(0)
}

fn cmd_formats() -> Result<i32, String> {
    println!("{:<16} {:<6} DESCRIPTION", "FORMAT", "R/W");
    for f in detect::ALL {
        println!(
            "{:<16} {:<6} {}",
            f.name(),
            if f.can_write() { "rw" } else { "r" },
            f.describe()
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_arguments_prints_help_and_succeeds() {
        assert_eq!(run(&[]), 0);
    }

    #[test]
    fn usage_errors_exit_1() {
        assert_eq!(run(&argv(&["frobnicate"])), 1, "unknown command");
        assert_eq!(run(&argv(&["convert", "--sideways"])), 1, "unknown option");
        assert_eq!(run(&argv(&["convert"])), 1, "convert without input");
        assert_eq!(
            run(&argv(&["convert", "a.json", "b.json"])),
            1,
            "two inputs"
        );
        assert_eq!(run(&argv(&["convert", "a.json"])), 1, "no -o");
        assert_eq!(
            run(&argv(&["merge", "only.json", "-o", "out.json"])),
            1,
            "single-input merge"
        );
    }

    #[test]
    fn missing_input_file_is_reported_not_panicked() {
        assert_eq!(run(&argv(&["inspect", "/nonexistent/vault.json"])), 1);
    }

    #[test]
    fn parse_args_collects_options_and_positionals() {
        let a = parse_args(&argv(&[
            "in.json", "-o", "out.xml", "--to", "keepass", "--json", "-q",
        ]))
        .unwrap();
        assert_eq!(a.positionals, vec!["in.json"]);
        assert_eq!(a.output.as_deref(), Some("out.xml"));
        assert_eq!(a.to.as_deref(), Some("keepass"));
        assert!(a.json && a.quiet);
        // '-' means stdio, so it must parse as a positional, not an option.
        let b = parse_args(&argv(&["-", "-o", "-"])).unwrap();
        assert_eq!(b.positionals, vec!["-"]);
        assert_eq!(b.output.as_deref(), Some("-"));
        // An option that needs a value must not silently swallow nothing.
        assert!(parse_args(&argv(&["--from"])).is_err());
    }
}
