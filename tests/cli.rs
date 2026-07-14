//! End-to-end tests that exercise the compiled `vaultvert` binary against the
//! committed example exports: conversion with a verified LOSSLESS verdict,
//! chained cross-format conversions, merging, report files, stdio piping and
//! failure modes. Everything runs against temp directories, fully offline.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_vaultvert")
}

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run vaultvert")
}

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vaultvert-cli-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Pull the vault digest out of `inspect --json` output without a JSON dep.
fn digest_of(path: &str) -> String {
    let out = run(&["inspect", path, "--json"]);
    assert!(out.status.success(), "inspect failed: {}", stderr(&out));
    let text = stdout(&out);
    let idx = text
        .find("\"digest\": \"")
        .expect("no digest in inspect --json")
        + 11;
    text[idx..idx + 64].to_string()
}

#[test]
fn version_and_help() {
    let v = run(&["--version"]);
    assert!(v.status.success());
    assert_eq!(stdout(&v).trim(), "vaultvert 0.1.0");
    let h = run(&["--help"]);
    assert!(h.status.success());
    for section in [
        "USAGE:",
        "COMMANDS:",
        "OPTIONS:",
        "convert",
        "merge",
        "inspect",
    ] {
        assert!(stdout(&h).contains(section), "help missing {section}");
    }
}

#[test]
fn inspect_reports_counts_coverage_and_warnings() {
    let input = examples().join("keepass-export.xml");
    let out = run(&["inspect", input.to_str().unwrap()]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("format  : keepass-xml"));
    assert!(
        text.contains("entries : 2"),
        "recycle-bin entry leaked into counts:\n{text}"
    );
    assert!(
        text.contains("Recycle Bin"),
        "missing skip warning:\n{text}"
    );
    assert!(text.contains("totp 1/2"), "coverage wrong:\n{text}");
}

#[test]
fn convert_bitwarden_to_keepass_is_verified_lossless() {
    let dir = tempdir("bw2kp");
    let input = examples().join("bitwarden-vault.json");
    let output = dir.join("vault.xml");
    let out = run(&[
        "convert",
        input.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "convert failed: {}", stderr(&out));
    let report = stderr(&out);
    assert!(
        report.contains("verdict: LOSSLESS"),
        "no lossless verdict:\n{report}"
    );
    assert!(report.contains("[match]"), "digest line missing:\n{report}");
    // The produced file is real KeePass XML carrying the same credentials.
    assert_eq!(
        digest_of(input.to_str().unwrap()),
        digest_of(output.to_str().unwrap())
    );
    let xml = fs::read_to_string(&output).unwrap();
    assert!(xml.contains("<KeePassFile>"));
    assert!(xml.contains("correct horse battery staple"));
}

#[test]
fn chained_conversions_across_all_three_formats_preserve_the_digest() {
    // bitwarden-json -> keepass-xml -> 1pif -> bitwarden-json: the digest
    // must survive the whole tour, not just one hop.
    let dir = tempdir("chain");
    let start = examples().join("bitwarden-vault.json");
    let hops = [dir.join("a.xml"), dir.join("b.1pif"), dir.join("c.json")];
    let mut prev = start.to_str().unwrap().to_string();
    for hop in &hops {
        let out = run(&["convert", &prev, "-o", hop.to_str().unwrap(), "--quiet"]);
        assert!(
            out.status.success(),
            "hop to {hop:?} failed: {}",
            stderr(&out)
        );
        prev = hop.to_str().unwrap().to_string();
    }
    assert_eq!(digest_of(start.to_str().unwrap()), digest_of(&prev));
}

#[test]
fn merge_dedupes_across_managers_and_preserves_conflicting_passwords() {
    let dir = tempdir("merge");
    let output = dir.join("merged.json");
    let bw = examples().join("bitwarden-vault.json");
    let kp = examples().join("keepass-export.xml");
    let op = examples().join("onepassword-export.1pif");
    let out = run(&[
        "merge",
        bw.to_str().unwrap(),
        kp.to_str().unwrap(),
        op.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "merge failed: {}", stderr(&out));
    let log = stderr(&out);
    // 4 + 2 + 2 entries in; "Corporate Mail" exists in all three sources.
    assert!(log.contains("8 entries in"), "unexpected stats:\n{log}");
    assert!(
        log.contains("2 duplicates merged"),
        "unexpected stats:\n{log}"
    );
    assert!(log.contains("6 entries out"), "unexpected stats:\n{log}");
    assert!(
        log.contains("verdict: LOSSLESS"),
        "merge output not verified:\n{log}"
    );
    let merged = fs::read_to_string(&output).unwrap();
    // Newest wins; both sources hold the same password here, so no conflict
    // stash — but the KeePass-only sibling URL union must be present.
    assert_eq!(merged.matches("\"name\": \"Corporate Mail\"").count(), 1);
    assert!(merged.contains("https://webmail.example.test"));
}

#[test]
fn report_file_is_written_in_json_when_asked() {
    let dir = tempdir("report");
    let input = examples().join("onepassword-export.1pif");
    let output = dir.join("out.json");
    let report = dir.join("report.json");
    let out = run(&[
        "convert",
        input.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--json",
        "--quiet",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).is_empty(), "--quiet leaked: {}", stderr(&out));
    let body = fs::read_to_string(&report).unwrap();
    assert!(body.contains("\"verdict\": \"LOSSLESS\""));
    assert!(body.contains("\"fieldMapping\""));
    assert!(
        body.contains("skipped 1 trashed"),
        "warning missing from report:\n{body}"
    );
}

#[test]
fn csv_input_works_but_csv_output_is_refused() {
    let dir = tempdir("csv");
    let input = examples().join("bitwarden-export.csv");
    let ok = run(&[
        "convert",
        input.to_str().unwrap(),
        "-o",
        dir.join("v.json").to_str().unwrap(),
        "--quiet",
    ]);
    assert!(ok.status.success(), "csv import failed: {}", stderr(&ok));
    let refused = run(&[
        "convert",
        input.to_str().unwrap(),
        "-o",
        dir.join("v.csv").to_str().unwrap(),
        "--to",
        "csv",
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).contains("refusing to write CSV"));
}

#[test]
fn stdio_piping_with_explicit_formats() {
    let mut child = Command::new(bin())
        .args([
            "convert",
            "-",
            "-o",
            "-",
            "--from",
            "bitwarden-json",
            "--to",
            "keepass-xml",
            "--quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = fs::read(examples().join("bitwarden-vault.json")).unwrap();
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let xml = stdout(&out);
    assert!(
        xml.starts_with("<?xml"),
        "stdout is not the converted vault"
    );
    assert!(xml.contains("Corporate Mail"));
}

#[test]
fn encrypted_bitwarden_export_fails_with_guidance_and_exit_1() {
    let dir = tempdir("enc");
    let input = dir.join("enc.json");
    fs::write(
        &input,
        r#"{"encrypted": true, "passwordProtected": true, "items": []}"#,
    )
    .unwrap();
    let out = run(&[
        "convert",
        input.to_str().unwrap(),
        "-o",
        dir.join("o.xml").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("re-export"),
        "unhelpful error: {}",
        stderr(&out)
    );
}
