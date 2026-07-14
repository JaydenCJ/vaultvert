//! The integrity report: proof that a conversion lost nothing.
//!
//! Writers record where every populated canonical field landed in the target
//! format (native slot vs. preserved custom field). After writing, the CLI
//! re-parses its own output with the target format's reader and compares the
//! order-independent vault digests. The verdict is LOSSLESS only when the
//! digests match and the entry counts agree — a claim that is checked, not
//! asserted.

use crate::json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Landed in a first-class slot of the target format.
    Native,
    /// Preserved verbatim as a custom field the reverse reader lifts back.
    Custom,
}

#[derive(Debug, Default, Clone)]
struct Row {
    native_target: String,
    custom_target: String,
    native: usize,
    custom: usize,
}

#[derive(Debug, Default, Clone)]
pub struct Report {
    pub source_name: String,
    pub source_format: String,
    pub target_name: String,
    pub target_format: String,
    pub source_entries: usize,
    pub target_entries: usize,
    pub source_digest: String,
    pub target_digest: String,
    pub warnings: Vec<String>,
    rows: BTreeMap<String, Row>,
}

impl Report {
    /// Start a report from the parsed source side; the target side is filled
    /// in by the write-and-verify step.
    pub fn for_source(
        name: &str,
        format: &str,
        entries: usize,
        digest: String,
        warnings: Vec<String>,
    ) -> Report {
        Report {
            source_name: name.to_string(),
            source_format: format.to_string(),
            source_entries: entries,
            source_digest: digest,
            warnings,
            ..Report::default()
        }
    }

    /// Record that canonical `field` was written to `target` (a label in the
    /// target format's vocabulary) with the given disposition, for one entry.
    pub fn note(&mut self, field: &str, target: &str, disp: Disposition) {
        let row = self.rows.entry(field.to_string()).or_default();
        match disp {
            Disposition::Native => {
                if row.native_target.is_empty() {
                    row.native_target = target.to_string();
                }
                row.native += 1;
            }
            Disposition::Custom => {
                if row.custom_target.is_empty() {
                    row.custom_target = target.to_string();
                }
                row.custom += 1;
            }
        }
    }

    pub fn warn(&mut self, msg: String) {
        self.warnings.push(msg);
    }

    pub fn lossless(&self) -> bool {
        !self.source_digest.is_empty()
            && self.source_digest == self.target_digest
            && self.source_entries == self.target_entries
    }

    pub fn verdict(&self) -> &'static str {
        if self.lossless() {
            "LOSSLESS"
        } else {
            "FAILED"
        }
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "vaultvert integrity report");
        let _ = writeln!(out, "==========================");
        let _ = writeln!(
            out,
            "source : {} ({}), {}",
            self.source_name,
            self.source_format,
            count(self.source_entries, "entry", "entries")
        );
        let _ = writeln!(
            out,
            "target : {} ({}), {}",
            self.target_name,
            self.target_format,
            count(self.target_entries, "entry", "entries")
        );
        let _ = writeln!(
            out,
            "digest : source {}\n         target {}  [{}]",
            short(&self.source_digest),
            short(&self.target_digest),
            if self.source_digest == self.target_digest {
                "match"
            } else {
                "MISMATCH"
            }
        );
        if !self.rows.is_empty() {
            let _ = writeln!(out, "\nfield mapping");
            let _ = writeln!(
                out,
                "  {:<12} -> {:<28} {:<10} entries",
                "field", "target", "as"
            );
            for (field, row) in &self.rows {
                if row.native > 0 {
                    let _ = writeln!(
                        out,
                        "  {:<12} -> {:<28} {:<10} {}",
                        field, row.native_target, "native", row.native
                    );
                }
                if row.custom > 0 {
                    let _ = writeln!(
                        out,
                        "  {:<12} -> {:<28} {:<10} {}",
                        field, row.custom_target, "custom", row.custom
                    );
                }
            }
        }
        if !self.warnings.is_empty() {
            let _ = writeln!(out, "\nwarnings");
            for w in &self.warnings {
                let _ = writeln!(out, "  - {w}");
            }
        }
        let _ = writeln!(
            out,
            "\nverdict: {} — {}",
            self.verdict(),
            if self.lossless() {
                format!(
                    "all {} round-trip verified",
                    count(self.target_entries, "entry", "entries")
                )
            } else {
                "output does NOT reproduce the source; do not delete the original".to_string()
            }
        );
        out
    }

    pub fn to_json(&self) -> Value {
        let rows: Vec<Value> = self
            .rows
            .iter()
            .map(|(field, row)| {
                let target = if row.native > 0 {
                    &row.native_target
                } else {
                    &row.custom_target
                };
                Value::obj(vec![
                    ("field", Value::s(field)),
                    ("target", Value::s(target)),
                    ("native", Value::Int(row.native as i64)),
                    ("custom", Value::Int(row.custom as i64)),
                ])
            })
            .collect();
        Value::obj(vec![
            (
                "source",
                Value::obj(vec![
                    ("name", Value::s(&self.source_name)),
                    ("format", Value::s(&self.source_format)),
                    ("entries", Value::Int(self.source_entries as i64)),
                    ("digest", Value::s(&self.source_digest)),
                ]),
            ),
            (
                "target",
                Value::obj(vec![
                    ("name", Value::s(&self.target_name)),
                    ("format", Value::s(&self.target_format)),
                    ("entries", Value::Int(self.target_entries as i64)),
                    ("digest", Value::s(&self.target_digest)),
                ]),
            ),
            ("fieldMapping", Value::Array(rows)),
            (
                "warnings",
                Value::Array(self.warnings.iter().map(|w| Value::s(w)).collect()),
            ),
            ("verdict", Value::s(self.verdict())),
        ])
    }
}

/// Format a counted noun ("1 entry", "4 entries") so user-facing text never
/// reads "1 entries" or hedges with "(s)".
pub fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {plural}")
    }
}

fn short(digest: &str) -> String {
    if digest.len() > 16 {
        format!("{}…{}", &digest[..8], &digest[digest.len() - 8..])
    } else {
        digest.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Report {
        Report {
            source_name: "in.json".into(),
            source_format: "bitwarden-json".into(),
            target_name: "out.xml".into(),
            target_format: "keepass-xml".into(),
            source_entries: 2,
            target_entries: 2,
            source_digest: "aa".repeat(32),
            target_digest: "aa".repeat(32),
            ..Report::default()
        }
    }

    #[test]
    fn matching_digests_and_counts_are_lossless() {
        assert!(base().lossless());
        assert_eq!(base().verdict(), "LOSSLESS");
    }

    #[test]
    fn digest_mismatch_fails_the_verdict() {
        let mut r = base();
        r.target_digest = "bb".repeat(32);
        assert!(!r.lossless());
        assert!(r.to_text().contains("MISMATCH"));
        assert!(r.to_text().contains("do not delete the original"));
    }

    #[test]
    fn entry_count_mismatch_fails_even_with_equal_digests() {
        // Defense in depth: digests of different multisets should already
        // differ, but the count check must stand on its own.
        let mut r = base();
        r.target_entries = 1;
        assert!(!r.lossless());
    }

    #[test]
    fn text_report_shows_native_and_custom_rows() {
        let mut r = base();
        r.note("totp", "otp", Disposition::Native);
        r.note("favorite", "vv:favorite", Disposition::Custom);
        let text = r.to_text();
        assert!(text.contains("totp"));
        assert!(text.contains("native"));
        assert!(text.contains("vv:favorite"));
        assert!(text.contains("custom"));
    }

    #[test]
    fn singular_counts_are_not_pluralized() {
        // Guards against "1 entries" — the report must read like a human
        // wrote it even for one-entry vaults.
        let mut r = base();
        r.source_entries = 1;
        r.target_entries = 1;
        let text = r.to_text();
        assert!(text.contains("(bitwarden-json), 1 entry\n"));
        assert!(text.contains("all 1 entry round-trip verified"));
        assert!(!text.contains("1 entries"));
        assert_eq!(count(2, "duplicate", "duplicates"), "2 duplicates");
    }

    #[test]
    fn json_report_carries_the_verdict_and_rows() {
        let mut r = base();
        r.note("title", "Title", Disposition::Native);
        let v = r.to_json();
        assert_eq!(v.get("verdict").as_str(), Some("LOSSLESS"));
        assert_eq!(v.get("fieldMapping").as_array().unwrap().len(), 1);
        assert_eq!(v.get("source").get("entries").as_i64(), Some(2));
    }
}
