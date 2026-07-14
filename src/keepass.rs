//! KeePass 2.x XML codec (read + write).
//!
//! Reads the file produced by KeePass `File > Export > KeePass XML (2.x)` and
//! compatible tools (KeePassXC, KeeWeb). Nested groups become `/`-separated
//! folder paths, `Protected`/`ProtectInMemory` strings become hidden fields,
//! the `otp` string convention maps to the canonical TOTP slot, and entries
//! inside the database's Recycle Bin are skipped (they were deleted for a
//! reason — a warning reports how many).

use crate::encode::{base64_decode, base64_encode};
use crate::model::{Entry, EntryKind, Field, Vault};
use crate::report::{Disposition, Report};
use crate::timefmt;
use crate::xml::{self, Element};

/// Seconds between 0001-01-01T00:00:00Z and the Unix epoch — KDBX 4 encodes
/// times as Base64 of a little-endian u64 of seconds since year 1.
const DOTNET_EPOCH_OFFSET: i64 = 62_135_596_800;

// --------------------------------------------------------------------- read

pub fn read(text: &str) -> Result<(Vault, Vec<String>), String> {
    let root = xml::parse(text).map_err(|e| format!("keepass xml: {e}"))?;
    if root.name != "KeePassFile" {
        return Err(format!(
            "keepass xml: root element is <{}>, expected <KeePassFile>",
            root.name
        ));
    }
    let recycle_uuid = root
        .child("Meta")
        .and_then(|m| m.child_text("RecycleBinUUID"))
        .unwrap_or("")
        .to_string();

    let top = root
        .child("Root")
        .and_then(|r| r.child("Group"))
        .ok_or("keepass xml: missing <Root><Group>")?;

    let mut vault = Vault::default();
    let mut skipped = 0usize;
    // The top-level group is the database itself; entries directly inside it
    // get no folder, subgroups start the path.
    walk_group(top, "", &recycle_uuid, &mut vault, &mut skipped)?;
    let mut warnings = Vec::new();
    if skipped > 0 {
        warnings.push(format!(
            "skipped {skipped} entr{} in the KeePass Recycle Bin",
            if skipped == 1 { "y" } else { "ies" }
        ));
    }
    Ok((vault, warnings))
}

fn walk_group(
    group: &Element,
    path: &str,
    recycle_uuid: &str,
    vault: &mut Vault,
    skipped: &mut usize,
) -> Result<(), String> {
    if !recycle_uuid.is_empty() && group.child_text("UUID") == Some(recycle_uuid) {
        *skipped += group_entry_count(group);
        return Ok(());
    }
    for entry_el in group.children_named("Entry") {
        vault.entries.push(parse_entry(entry_el, path)?);
    }
    for sub in group.children_named("Group") {
        let name = sub.child_text("Name").unwrap_or("").to_string();
        let sub_path = if path.is_empty() {
            name
        } else {
            format!("{path}/{name}")
        };
        walk_group(sub, &sub_path, recycle_uuid, vault, skipped)?;
    }
    Ok(())
}

fn group_entry_count(group: &Element) -> usize {
    group.children_named("Entry").count()
        + group
            .children_named("Group")
            .map(group_entry_count)
            .sum::<usize>()
}

fn parse_entry(el: &Element, path: &str) -> Result<Entry, String> {
    let mut e = Entry::new(EntryKind::Login, "");
    if !path.is_empty() {
        e.folder = Some(path.to_string());
    }
    if let Some(uuid_b64) = el.child_text("UUID") {
        if let Ok(raw) = base64_decode(uuid_b64) {
            if raw.len() == 16 {
                e.id = format!(
                    "{}-{}-{}-{}-{}",
                    crate::digest::hex(&raw[0..4]),
                    crate::digest::hex(&raw[4..6]),
                    crate::digest::hex(&raw[6..8]),
                    crate::digest::hex(&raw[8..10]),
                    crate::digest::hex(&raw[10..16]),
                );
            }
        }
    }
    for s in el.children_named("String") {
        let key = s.child_text("Key").unwrap_or("");
        let value_el = s.child("Value");
        let value = value_el.map(|v| v.text.clone()).unwrap_or_default();
        let hidden = value_el
            .map(|v| {
                v.attr("Protected") == Some("True") || v.attr("ProtectInMemory") == Some("True")
            })
            .unwrap_or(false);
        match key {
            "Title" => e.title = value,
            "UserName" => e.username = non_empty(value),
            "Password" => e.password = non_empty(value),
            "URL" => {
                if !value.is_empty() {
                    e.urls.insert(0, value);
                }
            }
            "Notes" => e.notes = non_empty(value),
            "otp" | "TOTP Seed" => {
                if e.totp.is_none() {
                    e.totp = non_empty(value);
                }
            }
            "" => {}
            _ => e.fields.push(Field {
                name: key.to_string(),
                value,
                hidden,
            }),
        }
    }
    if let Some(tags) = el.child_text("Tags") {
        e.tags = tags
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect();
    }
    if let Some(times) = el.child("Times") {
        e.created = times.child_text("CreationTime").and_then(parse_kp_time);
        e.modified = times
            .child_text("LastModificationTime")
            .and_then(parse_kp_time);
    }
    e.lift_spilled();
    e.ensure_id();
    Ok(e)
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// KeePass XML exports carry ISO 8601 times; KDBX 4 inner XML carries Base64
/// little-endian seconds since 0001-01-01. Accept both.
fn parse_kp_time(s: &str) -> Option<i64> {
    if let Ok(t) = timefmt::parse_rfc3339(s) {
        return Some(t);
    }
    let raw = base64_decode(s).ok()?;
    if raw.len() != 8 {
        return None;
    }
    let secs = i64::from_le_bytes(raw.try_into().ok()?);
    Some(secs - DOTNET_EPOCH_OFFSET)
}

// -------------------------------------------------------------------- write

pub fn write(vault: &Vault, rep: &mut Report) -> String {
    let mut root_group = Element::new("Group");
    root_group
        .children
        .push(Element::with_text("UUID", &uuid_to_b64("keepass-root")));
    root_group.children.push(Element::with_text("Name", "Root"));

    for entry in &vault.entries {
        let mut e = entry.clone();
        e.ensure_id();

        // Spill everything KeePass cannot hold natively.
        if e.kind() != EntryKind::Login {
            let kind = e.kind_label.clone();
            e.spill("kind", &kind, false);
            rep.note("kind", "vv:kind custom string", Disposition::Custom);
        } else {
            rep.note("kind", "(login is implicit)", Disposition::Native);
        }
        if e.favorite {
            e.spill("favorite", "true", false);
            rep.note("favorite", "vv:favorite custom string", Disposition::Custom);
        }
        let extra_urls: Vec<String> = if e.urls.len() > 1 {
            e.urls.split_off(1)
        } else {
            Vec::new()
        };
        for (i, u) in extra_urls.iter().enumerate() {
            e.fields
                .push(Field::new(&format!("vv:url.{}", i + 2), u, false));
            rep.note("url", "vv:url.N custom string", Disposition::Custom);
        }

        let mut el = Element::new("Entry");
        el.children
            .push(Element::with_text("UUID", &uuid_to_b64(&e.id)));
        rep.note("title", "String[Title]", Disposition::Native);
        push_string(&mut el, "Title", &e.title, false);
        if let Some(u) = &e.username {
            push_string(&mut el, "UserName", u, false);
            rep.note("username", "String[UserName]", Disposition::Native);
        }
        if let Some(p) = &e.password {
            push_string(&mut el, "Password", p, true);
            rep.note("password", "String[Password]", Disposition::Native);
        }
        if let Some(u) = e.urls.first() {
            push_string(&mut el, "URL", u, false);
            rep.note("url", "String[URL]", Disposition::Native);
        }
        if let Some(n) = &e.notes {
            push_string(&mut el, "Notes", n, false);
            rep.note("notes", "String[Notes]", Disposition::Native);
        }
        if let Some(t) = &e.totp {
            push_string(&mut el, "otp", t, true);
            rep.note("totp", "String[otp]", Disposition::Native);
        }
        for f in &e.fields {
            push_string(&mut el, &f.name, &f.value, f.hidden);
        }
        if !e.fields.is_empty() {
            rep.note("fields", "String[<name>]", Disposition::Native);
        }
        if !e.tags.is_empty() {
            el.children
                .push(Element::with_text("Tags", &e.tags.join(";")));
            rep.note("tags", "Tags", Disposition::Native);
        }
        if e.created.is_some() || e.modified.is_some() {
            let mut times = Element::new("Times");
            if let Some(t) = e.created {
                times
                    .children
                    .push(Element::with_text("CreationTime", &timefmt::to_rfc3339(t)));
                rep.note("created", "Times/CreationTime", Disposition::Native);
            }
            if let Some(t) = e.modified {
                times.children.push(Element::with_text(
                    "LastModificationTime",
                    &timefmt::to_rfc3339(t),
                ));
                rep.note(
                    "modified",
                    "Times/LastModificationTime",
                    Disposition::Native,
                );
            }
            el.children.push(times);
        }

        if let Some(folder) = &e.folder {
            rep.note("folder", "Group nesting", Disposition::Native);
            ensure_group(&mut root_group, folder.split('/'))
                .children
                .push(el);
        } else {
            root_group.children.push(el);
        }
    }

    let mut meta = Element::new("Meta");
    meta.children
        .push(Element::with_text("Generator", "vaultvert"));
    meta.children
        .push(Element::with_text("DatabaseName", "vaultvert export"));
    let mut root = Element::new("Root");
    root.children.push(root_group);
    let mut file = Element::new("KeePassFile");
    file.children.push(meta);
    file.children.push(root);
    xml::to_string(&file)
}

fn push_string(entry: &mut Element, key: &str, value: &str, protected: bool) {
    let mut s = Element::new("String");
    s.children.push(Element::with_text("Key", key));
    let mut v = Element::with_text("Value", value);
    if protected {
        // Exports are plaintext; the flag tells the importing client to
        // re-protect the value in memory.
        v.attrs.push(("ProtectInMemory".into(), "True".into()));
    }
    s.children.push(v);
    entry.children.push(s);
}

/// Find or create the nested group for a `/`-separated folder path.
fn ensure_group<'a, I: Iterator<Item = &'a str>>(root: &mut Element, path: I) -> &mut Element {
    let mut current = root;
    for part in path {
        let pos = current
            .children
            .iter()
            .position(|c| c.name == "Group" && c.child_text("Name") == Some(part));
        let idx = match pos {
            Some(i) => i,
            None => {
                let mut g = Element::new("Group");
                g.children.push(Element::with_text(
                    "UUID",
                    &uuid_to_b64(&format!("group\x1f{part}")),
                ));
                g.children.push(Element::with_text("Name", part));
                current.children.push(g);
                current.children.len() - 1
            }
        };
        current = &mut current.children[idx];
    }
    current
}

/// Deterministic 16-byte UUID for KeePass, Base64-encoded. If the entry id is
/// already a hex UUID we reuse its bytes so ids survive round-trips.
fn uuid_to_b64(id: &str) -> String {
    let hex_str: String = id.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let bytes: Vec<u8> = if hex_str.len() == 32 {
        (0..16)
            .map(|i| u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    } else {
        crate::digest::sha256(id.as_bytes())[..16].to_vec()
    };
    base64_encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_xml() -> String {
        let mut vault = Vault::default();
        let mut e = Entry::new(EntryKind::Login, "Router");
        e.username = Some("admin".into());
        e.password = Some("hunter2 & <friends>".into());
        e.urls = vec![
            "https://192.168.0.1".into(),
            "https://router.example.test".into(),
        ];
        e.notes = Some("line1\nline2".into());
        e.totp = Some("otpauth://totp/r?secret=JBSWY3DP".into());
        e.folder = Some("Home/Network".into());
        e.tags = vec!["infra".into(), "router".into()];
        e.favorite = true;
        e.fields.push(Field::new("serial", "SN-123", false));
        e.fields.push(Field::new("admin pin", "9876", true));
        e.created = Some(1_700_000_000);
        e.modified = Some(1_750_000_000);
        vault.entries.push(e);
        write(&vault, &mut Report::default())
    }

    #[test]
    fn write_then_read_round_trips_every_slot() {
        let (v, warnings) = read(&sample_xml()).unwrap();
        assert!(warnings.is_empty());
        let e = &v.entries[0];
        assert_eq!(e.title, "Router");
        assert_eq!(e.password.as_deref(), Some("hunter2 & <friends>"));
        assert_eq!(
            e.urls,
            vec!["https://192.168.0.1", "https://router.example.test"]
        );
        assert_eq!(e.folder.as_deref(), Some("Home/Network"));
        assert_eq!(e.tags, vec!["infra", "router"]);
        assert!(e.favorite);
        assert_eq!(e.totp.as_deref(), Some("otpauth://totp/r?secret=JBSWY3DP"));
        assert_eq!(e.fields.len(), 2);
        assert!(e.fields.iter().any(|f| f.name == "admin pin" && f.hidden));
        assert_eq!(e.created, Some(1_700_000_000));
        assert_eq!(e.modified, Some(1_750_000_000));
    }

    #[test]
    fn entry_uuid_survives_a_round_trip() {
        let (v1, _) = read(&sample_xml()).unwrap();
        let again = write(&v1, &mut Report::default());
        let (v2, _) = read(&again).unwrap();
        assert_eq!(v1.entries[0].id, v2.entries[0].id);
        assert_eq!(v1.digest(), v2.digest());
    }

    #[test]
    fn nested_groups_become_slash_paths() {
        let xml_doc = r#"<KeePassFile><Meta/><Root><Group><Name>DB</Name>
            <Group><Name>Work</Name><Group><Name>Servers</Name>
              <Entry><String><Key>Title</Key><Value>db01</Value></String></Entry>
            </Group></Group>
            <Entry><String><Key>Title</Key><Value>toplevel</Value></String></Entry>
        </Group></Root></KeePassFile>"#;
        let (v, _) = read(xml_doc).unwrap();
        let by_title = |t: &str| v.entries.iter().find(|e| e.title == t).unwrap().clone();
        assert_eq!(by_title("db01").folder.as_deref(), Some("Work/Servers"));
        assert_eq!(by_title("toplevel").folder, None);
    }

    #[test]
    fn recycle_bin_entries_are_skipped_with_warning() {
        let xml_doc = r#"<KeePassFile><Meta><RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID></Meta>
        <Root><Group><Name>DB</Name>
          <Entry><String><Key>Title</Key><Value>keep me</Value></String></Entry>
          <Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Recycle Bin</Name>
            <Entry><String><Key>Title</Key><Value>deleted</Value></String></Entry>
          </Group>
        </Group></Root></KeePassFile>"#;
        let (v, warnings) = read(xml_doc).unwrap();
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].title, "keep me");
        assert!(warnings[0].contains("skipped 1 entry"));
    }

    #[test]
    fn kdbx4_base64_times_are_understood() {
        // 0x0000000ECE1D5C80 LE == 63565596800 seconds since year 1
        // == 2015-04-15T15:33:20Z (63565596800 - 62135596800 = 1430000000).
        let b64 = crate::encode::base64_encode(&63_565_596_800i64.to_le_bytes());
        let xml_doc = format!(
            "<KeePassFile><Meta/><Root><Group><Name>DB</Name><Entry>\
             <String><Key>Title</Key><Value>t</Value></String>\
             <Times><CreationTime>{b64}</CreationTime></Times>\
             </Entry></Group></Root></KeePassFile>"
        );
        let (v, _) = read(&xml_doc).unwrap();
        assert_eq!(v.entries[0].created, Some(1_430_000_000));
    }

    #[test]
    fn protected_values_map_to_hidden_fields() {
        let xml_doc = r#"<KeePassFile><Meta/><Root><Group><Name>DB</Name><Entry>
          <String><Key>Title</Key><Value>x</Value></String>
          <String><Key>api key</Key><Value Protected="True">sk-000</Value></String>
        </Entry></Group></Root></KeePassFile>"#;
        let (v, _) = read(xml_doc).unwrap();
        let f = &v.entries[0].fields[0];
        assert!(f.hidden);
        assert_eq!(f.value, "sk-000");
    }

    #[test]
    fn non_keepass_xml_is_rejected() {
        assert!(read("<html></html>").unwrap_err().contains("KeePassFile"));
    }
}
