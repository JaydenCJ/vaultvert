//! Vault merging with duplicate detection.
//!
//! Two entries are considered the same credential when they agree on
//! (kind, normalized title, normalized username, primary URL host). Duplicates
//! are merged rather than dropped: URLs, tags and custom fields are unioned,
//! timestamps widen to min(created)/max(modified), and when passwords disagree
//! the newer one wins while the losing password is preserved in a custom field
//! — merging password files must never silently discard a secret.

use crate::model::{Entry, Vault};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MergeStats {
    pub inputs: usize,
    pub entries_in: usize,
    pub duplicates_merged: usize,
    pub password_conflicts: usize,
    pub entries_out: usize,
}

pub fn merge(vaults: &[Vault]) -> (Vault, MergeStats) {
    let mut stats = MergeStats {
        inputs: vaults.len(),
        ..MergeStats::default()
    };
    let mut out: Vec<Entry> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for vault in vaults {
        for entry in &vault.entries {
            stats.entries_in += 1;
            let key = dedupe_key(entry);
            match index.get(&key) {
                None => {
                    index.insert(key, out.len());
                    out.push(entry.clone());
                }
                Some(&i) => {
                    stats.duplicates_merged += 1;
                    let merged = merge_pair(&out[i], entry, &mut stats);
                    out[i] = merged;
                }
            }
        }
    }
    stats.entries_out = out.len();
    (Vault { entries: out }, stats)
}

/// Identity key for duplicate detection. Uses `\x1f` framing like the core
/// digest so field boundaries cannot alias.
pub fn dedupe_key(e: &Entry) -> String {
    format!(
        "{}\x1f{}\x1f{}\x1f{}",
        e.kind_label,
        e.title.trim().to_lowercase(),
        e.username.as_deref().unwrap_or("").trim().to_lowercase(),
        e.urls.first().map(|u| url_host(u)).unwrap_or_default(),
    )
}

/// Extract a normalized host from a URL-ish string: scheme and path stripped,
/// `www.` dropped, lowercased. Non-URL strings normalize to themselves.
pub fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    host.trim().trim_start_matches("www.").to_lowercase()
}

fn merge_pair(a: &Entry, b: &Entry, stats: &mut MergeStats) -> Entry {
    // Prefer the entry with the newer modification time; on a tie (or when
    // neither carries timestamps) the earlier input wins, keeping the
    // operation deterministic with respect to argument order.
    let (winner, loser) = if b.modified.unwrap_or(i64::MIN) > a.modified.unwrap_or(i64::MIN) {
        (b, a)
    } else {
        (a, b)
    };
    let mut e = winner.clone();

    if e.password.is_none() {
        e.password = loser.password.clone();
    } else if let Some(lost) = &loser.password {
        if Some(lost) != e.password.as_ref() {
            stats.password_conflicts += 1;
            e.fields.push(crate::model::Field::new(
                "password (superseded by merge)",
                lost,
                true,
            ));
        }
    }
    if e.username.is_none() {
        e.username = loser.username.clone();
    }
    if e.notes.is_none() {
        e.notes = loser.notes.clone();
    }
    if e.totp.is_none() {
        e.totp = loser.totp.clone();
    }
    if e.folder.is_none() {
        e.folder = loser.folder.clone();
    }
    e.favorite = e.favorite || loser.favorite;
    for url in &loser.urls {
        if !e.urls.contains(url) {
            e.urls.push(url.clone());
        }
    }
    for tag in &loser.tags {
        if !e.tags.contains(tag) {
            e.tags.push(tag.clone());
        }
    }
    for f in &loser.fields {
        if !e
            .fields
            .iter()
            .any(|g| g.name == f.name && g.value == f.value)
        {
            e.fields.push(f.clone());
        }
    }
    e.created = match (winner.created, loser.created) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    };
    e.modified = match (winner.modified, loser.modified) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, y) => x.or(y),
    };
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EntryKind;

    fn entry(title: &str, user: &str, url: &str) -> Entry {
        let mut e = Entry::new(EntryKind::Login, title);
        e.username = Some(user.into());
        e.password = Some("pw".into());
        if !url.is_empty() {
            e.urls = vec![url.into()];
        }
        e
    }

    #[test]
    fn url_host_normalizes_scheme_www_path_and_case() {
        assert_eq!(
            url_host("https://www.Mail.Example.TEST/inbox?x=1"),
            "mail.example.test"
        );
        assert_eq!(url_host("mail.example.test"), "mail.example.test");
        assert_eq!(
            url_host("https://user@host.example.test/x"),
            "host.example.test"
        );
    }

    #[test]
    fn identical_entries_across_vaults_collapse_to_one() {
        let v1 = Vault {
            entries: vec![entry("Mail", "kim", "https://mail.example.test")],
        };
        let v2 = Vault {
            entries: vec![entry("mail ", "KIM", "http://www.mail.example.test/login")],
        };
        let (merged, stats) = merge(&[v1, v2]);
        assert_eq!(merged.entries.len(), 1);
        assert_eq!(stats.duplicates_merged, 1);
        assert_eq!(stats.password_conflicts, 0);
    }

    #[test]
    fn different_usernames_do_not_collapse() {
        let v1 = Vault {
            entries: vec![entry("Mail", "kim", "https://mail.example.test")],
        };
        let v2 = Vault {
            entries: vec![entry("Mail", "sam", "https://mail.example.test")],
        };
        let (merged, _) = merge(&[v1, v2]);
        assert_eq!(merged.entries.len(), 2);
    }

    #[test]
    fn newer_password_wins_and_older_is_preserved() {
        let mut old = entry("Mail", "kim", "https://mail.example.test");
        old.password = Some("old-pw".into());
        old.modified = Some(100);
        let mut new = entry("Mail", "kim", "https://mail.example.test");
        new.password = Some("new-pw".into());
        new.modified = Some(200);
        // Argument order must not matter for the winner.
        for vaults in [
            [
                Vault {
                    entries: vec![old.clone()],
                },
                Vault {
                    entries: vec![new.clone()],
                },
            ],
            [
                Vault {
                    entries: vec![new.clone()],
                },
                Vault {
                    entries: vec![old.clone()],
                },
            ],
        ] {
            let (merged, stats) = merge(&vaults);
            let e = &merged.entries[0];
            assert_eq!(e.password.as_deref(), Some("new-pw"));
            assert_eq!(stats.password_conflicts, 1);
            let stash = e
                .fields
                .iter()
                .find(|f| f.name.contains("superseded"))
                .unwrap();
            assert_eq!(stash.value, "old-pw");
            assert!(stash.hidden);
        }
    }

    #[test]
    fn urls_tags_and_fields_are_unioned_without_duplicates() {
        let mut a = entry("Mail", "kim", "https://mail.example.test");
        a.tags = vec!["work".into()];
        a.fields.push(crate::model::Field::new("pin", "1", false));
        let mut b = entry("Mail", "kim", "https://mail.example.test");
        b.urls.push("https://webmail.example.test".into());
        b.tags = vec!["work".into(), "email".into()];
        b.fields.push(crate::model::Field::new("pin", "1", false));
        let (merged, _) = merge(&[Vault { entries: vec![a] }, Vault { entries: vec![b] }]);
        let e = &merged.entries[0];
        assert_eq!(e.urls.len(), 2);
        assert_eq!(e.tags, vec!["work", "email"]);
        assert_eq!(e.fields.iter().filter(|f| f.name == "pin").count(), 1);
    }

    #[test]
    fn timestamps_widen_to_earliest_created_latest_modified() {
        let mut a = entry("Mail", "kim", "");
        a.created = Some(50);
        a.modified = Some(300);
        let mut b = entry("Mail", "kim", "");
        b.created = Some(10);
        b.modified = Some(100);
        let (merged, _) = merge(&[Vault { entries: vec![a] }, Vault { entries: vec![b] }]);
        assert_eq!(merged.entries[0].created, Some(10));
        assert_eq!(merged.entries[0].modified, Some(300));
    }

    #[test]
    fn merge_fills_missing_slots_from_the_loser() {
        let mut a = entry("Mail", "kim", "https://mail.example.test");
        a.modified = Some(200);
        a.totp = None;
        a.notes = None;
        let mut b = entry("Mail", "kim", "https://mail.example.test");
        b.modified = Some(100);
        b.totp = Some("otpauth://totp/m?secret=X".into());
        b.notes = Some("recovery in safe".into());
        let (merged, _) = merge(&[Vault { entries: vec![a] }, Vault { entries: vec![b] }]);
        assert_eq!(
            merged.entries[0].totp.as_deref(),
            Some("otpauth://totp/m?secret=X")
        );
        assert_eq!(merged.entries[0].notes.as_deref(), Some("recovery in safe"));
    }

    #[test]
    fn entries_without_urls_dedupe_on_title_and_username() {
        let v1 = Vault {
            entries: vec![entry("Wifi", "", "")],
        };
        let v2 = Vault {
            entries: vec![entry("wifi", "", "")],
        };
        let (merged, stats) = merge(&[v1, v2]);
        assert_eq!(merged.entries.len(), 1);
        assert_eq!(stats.entries_in, 2);
        assert_eq!(stats.entries_out, 1);
    }
}
