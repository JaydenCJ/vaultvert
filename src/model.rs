//! The canonical vault model every format is mapped onto.
//!
//! Readers translate a vendor export into `Vault`/`Entry`; writers translate
//! it back out. Anything a target format cannot represent natively is spilled
//! into `fields` under a reserved `vv:` name so the reverse reader can lift it
//! back — that is the mechanism behind the lossless round-trip guarantee.

use crate::digest;

/// Reserved custom-field prefix used to spill canonical slots into formats
/// that have no native place for them (e.g. a password on a secure note).
pub const SPILL_PREFIX: &str = "vv:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Login,
    Note,
    Card,
    Identity,
}

impl EntryKind {
    pub fn label(self) -> &'static str {
        match self {
            EntryKind::Login => "login",
            EntryKind::Note => "note",
            EntryKind::Card => "card",
            EntryKind::Identity => "identity",
        }
    }

    pub fn from_label(s: &str) -> Option<EntryKind> {
        match s {
            "login" => Some(EntryKind::Login),
            "note" => Some(EntryKind::Note),
            "card" => Some(EntryKind::Card),
            "identity" => Some(EntryKind::Identity),
            _ => None,
        }
    }
}

/// One custom key/value attached to an entry. `hidden` marks values that a
/// UI should conceal (Bitwarden field type 1, KeePass protected strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}

impl Field {
    pub fn new(name: &str, value: &str, hidden: bool) -> Field {
        Field {
            name: name.to_string(),
            value: value.to_string(),
            hidden,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub kind_label: String,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub fields: Vec<Field>,
    /// Unix seconds, UTC.
    pub created: Option<i64>,
    pub modified: Option<i64>,
}

impl Entry {
    pub fn new(kind: EntryKind, title: &str) -> Entry {
        Entry {
            kind_label: kind.label().to_string(),
            title: title.to_string(),
            ..Entry::default()
        }
    }

    pub fn kind(&self) -> EntryKind {
        EntryKind::from_label(&self.kind_label).unwrap_or(EntryKind::Login)
    }

    /// Ensure the entry has a stable id: derive one deterministically from the
    /// core credential material so repeated runs produce identical output.
    pub fn ensure_id(&mut self) {
        if self.id.is_empty() {
            self.id = deterministic_uuid(&self.canonical_core());
        }
    }

    /// Canonical serialization of the fields that MUST survive any
    /// conversion. Field separators use `\x1f` (unit separator) so no
    /// credential text can collide with the framing.
    pub fn canonical_core(&self) -> String {
        let mut urls = self.urls.clone();
        urls.sort();
        let mut out = String::new();
        for part in [
            self.kind_label.as_str(),
            self.title.as_str(),
            self.username.as_deref().unwrap_or(""),
            self.password.as_deref().unwrap_or(""),
            &urls.join("\x1e"),
            self.notes.as_deref().unwrap_or(""),
            self.totp.as_deref().unwrap_or(""),
        ] {
            out.push_str(part);
            out.push('\x1f');
        }
        out
    }

    /// SHA-256 over the canonical core, as lowercase hex.
    pub fn core_digest(&self) -> String {
        digest::hex(&digest::sha256(self.canonical_core().as_bytes()))
    }

    /// Push a spilled canonical slot as a reserved custom field.
    pub fn spill(&mut self, slot: &str, value: &str, hidden: bool) {
        self.fields
            .push(Field::new(&format!("{SPILL_PREFIX}{slot}"), value, hidden));
    }

    /// Lift reserved `vv:` fields back into their canonical slots. Called by
    /// every reader after vendor-specific parsing.
    pub fn lift_spilled(&mut self) {
        let mut keep = Vec::with_capacity(self.fields.len());
        for f in self.fields.drain(..) {
            match f.name.strip_prefix(SPILL_PREFIX) {
                Some("username") if self.username.is_none() => self.username = Some(f.value),
                Some("password") if self.password.is_none() => self.password = Some(f.value),
                Some("totp") if self.totp.is_none() => self.totp = Some(f.value),
                Some("notes") if self.notes.is_none() => self.notes = Some(f.value),
                Some(u) if u == "url" || u.starts_with("url.") => self.urls.push(f.value),
                Some("favorite") => self.favorite = f.value == "true",
                Some("tags") => {
                    self.tags.extend(f.value.split(',').map(|t| t.to_string()));
                }
                Some("kind") => {
                    if EntryKind::from_label(&f.value).is_some() {
                        self.kind_label = f.value;
                    }
                }
                _ => keep.push(f),
            }
        }
        self.fields = keep;
    }
}

/// UUID-shaped hex string derived from a seed via SHA-256; used wherever the
/// target format needs an id the source did not carry (entries, folders).
pub fn deterministic_uuid(seed: &str) -> String {
    let h = digest::sha256(seed.as_bytes());
    format!(
        "{}-{}-{}-{}-{}",
        digest::hex(&h[0..4]),
        digest::hex(&h[4..6]),
        digest::hex(&h[6..8]),
        digest::hex(&h[8..10]),
        digest::hex(&h[10..16]),
    )
}

#[derive(Debug, Clone, Default)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

impl Vault {
    /// Order-independent digest over every entry's core digest: the sorted
    /// per-entry digests are concatenated and hashed again, so two vaults
    /// match iff they hold the same multiset of core credentials.
    pub fn digest(&self) -> String {
        let mut per: Vec<String> = self.entries.iter().map(|e| e.core_digest()).collect();
        per.sort();
        digest::hex(&digest::sha256(per.join("\n").as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Entry {
        let mut e = Entry::new(EntryKind::Login, "example");
        e.username = Some("kim".into());
        e.password = Some("pw".into());
        e.urls = vec![
            "https://a.example.test".into(),
            "https://b.example.test".into(),
        ];
        e
    }

    #[test]
    fn core_digest_ignores_url_order_but_sees_password_changes() {
        let a = login();
        let mut b = login();
        b.urls.reverse();
        assert_eq!(a.core_digest(), b.core_digest());
        b.password = Some("other".into());
        assert_ne!(a.core_digest(), b.core_digest());
    }

    #[test]
    fn field_concatenation_cannot_alias_across_slots() {
        // "ab" + "" must not hash equal to "a" + "b" — the unit separator
        // framing is what protects against this class of collision.
        let mut a = Entry::new(EntryKind::Login, "ab");
        a.username = Some("".into());
        let mut b = Entry::new(EntryKind::Login, "a");
        b.username = Some("b".into());
        assert_ne!(a.core_digest(), b.core_digest());
    }

    #[test]
    fn vault_digest_is_order_independent() {
        let mut e2 = login();
        e2.title = "second".into();
        let v1 = Vault {
            entries: vec![login(), e2.clone()],
        };
        let v2 = Vault {
            entries: vec![e2, login()],
        };
        assert_eq!(v1.digest(), v2.digest());
    }

    #[test]
    fn vault_digest_counts_duplicates() {
        // An XOR-style combiner would let duplicate entries cancel out; the
        // sorted-concat design must keep multiplicity visible.
        let v1 = Vault {
            entries: vec![login()],
        };
        let v2 = Vault {
            entries: vec![login(), login()],
        };
        assert_ne!(v1.digest(), v2.digest());
    }

    #[test]
    fn ensure_id_is_deterministic_and_uuid_shaped() {
        let mut a = login();
        let mut b = login();
        a.ensure_id();
        b.ensure_id();
        assert_eq!(a.id, b.id);
        let parts: Vec<&str> = a.id.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
    }

    #[test]
    fn spill_then_lift_round_trips_canonical_slots() {
        let mut e = Entry::new(EntryKind::Note, "server note");
        e.spill("password", "s3cret", true);
        e.spill("url", "https://c.example.test", false);
        e.spill("favorite", "true", false);
        e.spill("kind", "card", false);
        e.fields.push(Field::new("pin", "1234", true));
        e.lift_spilled();
        assert_eq!(e.password.as_deref(), Some("s3cret"));
        assert_eq!(e.urls, vec!["https://c.example.test".to_string()]);
        assert!(e.favorite);
        assert_eq!(e.kind(), EntryKind::Card);
        // Ordinary custom fields survive untouched.
        assert_eq!(e.fields, vec![Field::new("pin", "1234", true)]);
    }

    #[test]
    fn lift_never_overwrites_a_native_value() {
        let mut e = Entry::new(EntryKind::Login, "x");
        e.password = Some("native".into());
        e.spill("password", "spilled", true);
        e.lift_spilled();
        assert_eq!(e.password.as_deref(), Some("native"));
    }
}
