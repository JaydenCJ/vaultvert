//! 1Password 1PIF codec (read + write).
//!
//! 1PIF is the plaintext interchange format written by 1Password's
//! `File > Export > All Items (.1pif)`: one JSON record per line, each
//! followed by a `***5642bee8-a5ff-11dc-8314-0800200c9a66***` separator line.
//! Handled record types: `webforms.WebForm` and `passwords.Password` (logins),
//! `securenotes.SecureNote`, `wallet.financial.CreditCard`,
//! `identities.Identity`, and `system.folder.Regular` (folder definitions).
//! Records flagged `trashed` are skipped and reported.

use crate::json::{self, Value};
use crate::model::{Entry, EntryKind, Field, Vault};
use crate::report::{Disposition, Report};

pub const SEPARATOR: &str = "***5642bee8-a5ff-11dc-8314-0800200c9a66***";

// --------------------------------------------------------------------- read

pub fn read(text: &str) -> Result<(Vault, Vec<String>), String> {
    let mut records = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line == SEPARATOR {
            continue;
        }
        let rec = json::parse(line).map_err(|e| format!("1pif line {}: {e}", n + 1))?;
        records.push(rec);
    }

    // First pass: folder records (they may appear after the items using them).
    let mut folders = std::collections::BTreeMap::new();
    for rec in &records {
        if rec.str_of("typeName").as_deref() == Some("system.folder.Regular") {
            if let (Some(uuid), Some(title)) = (rec.str_of("uuid"), rec.str_of("title")) {
                folders.insert(uuid, title);
            }
        }
    }

    let mut vault = Vault::default();
    let mut trashed = 0usize;
    for rec in &records {
        let type_name = rec.str_of("typeName").unwrap_or_default();
        let kind = match type_name.as_str() {
            "webforms.WebForm" | "passwords.Password" => EntryKind::Login,
            "securenotes.SecureNote" => EntryKind::Note,
            "wallet.financial.CreditCard" => EntryKind::Card,
            "identities.Identity" => EntryKind::Identity,
            _ => continue, // folders, attachments, unknown types
        };
        if rec.get("trashed").as_bool() == Some(true) {
            trashed += 1;
            continue;
        }
        let mut e = Entry::new(kind, &rec.str_of("title").unwrap_or_default());
        e.id = rec.str_of("uuid").unwrap_or_default();
        e.folder = rec
            .str_of("folderUuid")
            .and_then(|u| folders.get(&u).cloned());
        e.created = rec.get("createdAt").as_i64();
        e.modified = rec.get("updatedAt").as_i64();
        e.favorite = rec
            .get("openContents")
            .get("faveIndex")
            .as_i64()
            .unwrap_or(0)
            > 0
            || rec.get("faveIndex").as_i64().unwrap_or(0) > 0;
        for tag in rec
            .get("openContents")
            .get("tags")
            .as_array()
            .unwrap_or(&[])
        {
            if let Some(t) = tag.as_str() {
                e.tags.push(t.to_string());
            }
        }

        if let Some(loc) = rec.str_of("location") {
            e.urls.push(loc);
        }
        let sc = rec.get("secureContents");
        e.notes = sc.str_of("notesPlain").filter(|n| !n.is_empty());
        if kind == EntryKind::Login {
            e.password = sc.str_of("password"); // passwords.Password records
        }
        for url in sc.get("URLs").as_array().unwrap_or(&[]) {
            if let Some(u) = url.str_of("url") {
                if !e.urls.contains(&u) {
                    e.urls.push(u);
                }
            }
        }
        // Web-form fields carry the login designations.
        for f in sc.get("fields").as_array().unwrap_or(&[]) {
            let value = f.str_of("value").unwrap_or_default();
            match f.str_of("designation").as_deref() {
                Some("username") => e.username = Some(value),
                Some("password") => e.password = Some(value),
                _ => {}
            }
        }
        // Sections hold everything else, including TOTP (field name TOTP_*).
        for section in sc.get("sections").as_array().unwrap_or(&[]) {
            for f in section.get("fields").as_array().unwrap_or(&[]) {
                let name = f.str_of("n").unwrap_or_default();
                let title = f.str_of("t").unwrap_or_default();
                let value = match f.get("v") {
                    Value::Int(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    v => v.as_str().unwrap_or("").to_string(),
                };
                if value.is_empty() {
                    continue;
                }
                if name.starts_with("TOTP_") {
                    e.totp = Some(value);
                    continue;
                }
                let label = if title.is_empty() { name } else { title };
                let hidden = f.str_of("k").as_deref() == Some("concealed");
                e.fields.push(Field {
                    name: label,
                    value,
                    hidden,
                });
            }
        }
        e.lift_spilled();
        e.ensure_id();
        vault.entries.push(e);
    }
    if vault.entries.is_empty() && records.iter().all(|r| r.str_of("typeName").is_none()) {
        return Err("1pif: no recognizable records found".into());
    }
    let mut warnings = Vec::new();
    if trashed > 0 {
        warnings.push(format!(
            "skipped {}",
            crate::report::count(trashed, "trashed 1Password item", "trashed 1Password items")
        ));
    }
    Ok((vault, warnings))
}

// -------------------------------------------------------------------- write

pub fn write(vault: &Vault, rep: &mut Report) -> String {
    let mut out = String::new();
    let mut folder_uuids = std::collections::BTreeMap::new();

    // Folder records first so importers resolve folderUuid immediately.
    for entry in &vault.entries {
        if let Some(folder) = &entry.folder {
            folder_uuids
                .entry(folder.clone())
                .or_insert_with(|| pif_uuid(&format!("folder\x1f{folder}")));
        }
    }
    for (name, uuid) in &folder_uuids {
        let rec = Value::obj(vec![
            ("uuid", Value::s(uuid)),
            ("typeName", Value::s("system.folder.Regular")),
            ("title", Value::s(name)),
        ]);
        push_record(&mut out, &rec);
    }

    for entry in &vault.entries {
        let mut e = entry.clone();
        e.ensure_id();
        let type_name = match e.kind() {
            EntryKind::Login => "webforms.WebForm",
            EntryKind::Note => "securenotes.SecureNote",
            EntryKind::Card => "wallet.financial.CreditCard",
            EntryKind::Identity => "identities.Identity",
        };
        rep.note("title", "title", Disposition::Native);
        rep.note("kind", "typeName", Disposition::Native);
        let mut rec = vec![
            ("uuid", Value::s(&pif_uuid(&e.id))),
            ("typeName", Value::s(type_name)),
            ("title", Value::s(&e.title)),
        ];
        if let Some(folder) = &e.folder {
            rec.push(("folderUuid", Value::s(&folder_uuids[folder])));
            rep.note("folder", "folderUuid", Disposition::Native);
        }
        if let Some(t) = e.created {
            rec.push(("createdAt", Value::Int(t)));
            rep.note("created", "createdAt", Disposition::Native);
        }
        if let Some(t) = e.modified {
            rec.push(("updatedAt", Value::Int(t)));
            rep.note("modified", "updatedAt", Disposition::Native);
        }
        let mut open = Vec::new();
        if e.favorite {
            open.push(("faveIndex", Value::Int(1)));
            rep.note("favorite", "openContents.faveIndex", Disposition::Native);
        }
        if !e.tags.is_empty() {
            open.push((
                "tags",
                Value::Array(e.tags.iter().map(|t| Value::s(t)).collect()),
            ));
            rep.note("tags", "openContents.tags", Disposition::Native);
        }
        if !open.is_empty() {
            rec.push(("openContents", Value::obj(open)));
        }

        let mut sc: Vec<(&str, Value)> = Vec::new();
        if let Some(n) = &e.notes {
            sc.push(("notesPlain", Value::s(n)));
            rep.note("notes", "secureContents.notesPlain", Disposition::Native);
        }
        if let Some(first) = e.urls.first() {
            rec.push(("location", Value::s(first)));
            rep.note("url", "location", Disposition::Native);
        }
        if e.urls.len() > 1 {
            let urls: Vec<Value> = e.urls[1..]
                .iter()
                .map(|u| Value::obj(vec![("label", Value::s("website")), ("url", Value::s(u))]))
                .collect();
            sc.push(("URLs", Value::Array(urls)));
            rep.note("url", "secureContents.URLs[]", Disposition::Native);
        }
        let mut form_fields = Vec::new();
        if let Some(u) = &e.username {
            form_fields.push(designated("username", "T", u));
            rep.note(
                "username",
                "fields[designation=username]",
                Disposition::Native,
            );
        }
        if let Some(p) = &e.password {
            form_fields.push(designated("password", "P", p));
            rep.note(
                "password",
                "fields[designation=password]",
                Disposition::Native,
            );
        }
        if !form_fields.is_empty() {
            sc.push(("fields", Value::Array(form_fields)));
        }

        let mut section_fields = Vec::new();
        if let Some(t) = &e.totp {
            section_fields.push(Value::obj(vec![
                ("k", Value::s("concealed")),
                ("n", Value::s("TOTP_VAULTVERT")),
                ("t", Value::s("one-time password")),
                ("v", Value::s(t)),
            ]));
            rep.note("totp", "section field TOTP_*", Disposition::Native);
        }
        for f in &e.fields {
            section_fields.push(Value::obj(vec![
                ("k", Value::s(if f.hidden { "concealed" } else { "string" })),
                ("n", Value::s(&f.name)),
                ("t", Value::s(&f.name)),
                ("v", Value::s(&f.value)),
            ]));
        }
        if !e.fields.is_empty() {
            rep.note("fields", "section fields", Disposition::Native);
        }
        if !section_fields.is_empty() {
            sc.push((
                "sections",
                Value::Array(vec![Value::obj(vec![
                    ("title", Value::s("vaultvert")),
                    ("name", Value::s("vaultvert")),
                    ("fields", Value::Array(section_fields)),
                ])]),
            ));
        }
        rec.push(("secureContents", Value::obj(sc)));
        push_record(&mut out, &Value::obj(rec));
    }
    out
}

fn designated(designation: &str, type_code: &str, value: &str) -> Value {
    Value::obj(vec![
        ("designation", Value::s(designation)),
        ("name", Value::s(designation)),
        ("type", Value::s(type_code)),
        ("value", Value::s(value)),
    ])
}

/// 1PIF uuids are 32 uppercase hex chars; reuse the entry's hex when present.
fn pif_uuid(id: &str) -> String {
    let hex_str: String = id.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_str.len() == 32 {
        hex_str.to_uppercase()
    } else {
        crate::digest::hex(&crate::digest::sha256(id.as_bytes())[..16]).to_uppercase()
    }
}

fn push_record(out: &mut String, rec: &Value) {
    // 1PIF is line-oriented: compact JSON, one record per line.
    let pretty = json::to_pretty(rec);
    let compact: String = compact_json(&pretty);
    out.push_str(&compact);
    out.push('\n');
    out.push_str(SEPARATOR);
    out.push('\n');
}

/// Re-serialize pretty JSON onto one line without touching string contents.
fn compact_json(pretty: &str) -> String {
    let mut out = String::with_capacity(pretty.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in pretty.chars() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                out.push(ch);
            }
            ' ' | '\n' | '\t' => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_1pif() -> String {
        let mut out = String::new();
        for rec in [
            r#"{"uuid":"F0F0","typeName":"system.folder.Regular","title":"Personal"}"#,
            r#"{"uuid":"AB01","typeName":"webforms.WebForm","title":"Forum","location":"https://forum.example.test","folderUuid":"F0F0","createdAt":1600000000,"updatedAt":1650000000,"openContents":{"tags":["community"],"faveIndex":2},"secureContents":{"notesPlain":"my forum login","fields":[{"designation":"username","name":"login","type":"T","value":"kim"},{"designation":"password","name":"pw","type":"P","value":"s3cret!"}],"sections":[{"title":"extra","fields":[{"k":"concealed","n":"TOTP_ABC","t":"one-time password","v":"otpauth://totp/f?secret=GEZDGNBV"},{"k":"string","n":"member id","t":"member id","v":"778"}]}]}}"#,
            r#"{"uuid":"AB02","typeName":"securenotes.SecureNote","title":"Recovery codes","secureContents":{"notesPlain":"aaa-bbb\nccc-ddd"}}"#,
            r#"{"uuid":"AB03","typeName":"webforms.WebForm","title":"Old junk","trashed":true,"secureContents":{}}"#,
        ] {
            out.push_str(rec);
            out.push('\n');
            out.push_str(SEPARATOR);
            out.push('\n');
        }
        out
    }

    #[test]
    fn reads_webform_with_designations_totp_and_folder() {
        let (v, _) = read(&sample_1pif()).unwrap();
        let e = &v.entries[0];
        assert_eq!(e.title, "Forum");
        assert_eq!(e.username.as_deref(), Some("kim"));
        assert_eq!(e.password.as_deref(), Some("s3cret!"));
        assert_eq!(e.totp.as_deref(), Some("otpauth://totp/f?secret=GEZDGNBV"));
        assert_eq!(e.folder.as_deref(), Some("Personal"));
        assert_eq!(e.tags, vec!["community"]);
        assert!(e.favorite);
        assert_eq!(e.fields[0].name, "member id");
        assert_eq!(e.created, Some(1_600_000_000));
    }

    #[test]
    fn trashed_items_are_skipped_and_reported() {
        let (v, warnings) = read(&sample_1pif()).unwrap();
        assert_eq!(v.entries.len(), 2);
        assert!(warnings[0].contains("1 trashed"));
    }

    #[test]
    fn secure_note_maps_to_note_kind() {
        let (v, _) = read(&sample_1pif()).unwrap();
        assert_eq!(v.entries[1].kind(), EntryKind::Note);
        assert_eq!(v.entries[1].notes.as_deref(), Some("aaa-bbb\nccc-ddd"));
    }

    #[test]
    fn write_then_read_is_digest_identical() {
        let (v, _) = read(&sample_1pif()).unwrap();
        let out = write(&v, &mut Report::default());
        let (back, _) = read(&out).unwrap();
        assert_eq!(back.digest(), v.digest());
        assert_eq!(back.entries[0].tags, vec!["community"]);
        assert!(back.entries[0].favorite);
        // 1PIF is line-oriented: every record on one line, separator after.
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len() % 2, 0);
        for pair in lines.chunks(2) {
            assert!(
                pair[0].starts_with('{'),
                "record not on one line: {}",
                pair[0]
            );
            assert_eq!(pair[1], SEPARATOR);
        }
    }

    #[test]
    fn multiline_note_survives_compact_serialization() {
        let mut e = Entry::new(EntryKind::Note, "n");
        e.notes = Some("a\nb \"quoted\" \\slash".into());
        let out = write(&Vault { entries: vec![e] }, &mut Report::default());
        let (back, _) = read(&out).unwrap();
        assert_eq!(
            back.entries[0].notes.as_deref(),
            Some("a\nb \"quoted\" \\slash")
        );
    }

    #[test]
    fn passwords_password_record_type_is_read() {
        let text = format!(
            "{}\n{}\n",
            r#"{"uuid":"CD01","typeName":"passwords.Password","title":"legacy","secureContents":{"password":"only-a-password"}}"#,
            SEPARATOR
        );
        let (v, _) = read(&text).unwrap();
        assert_eq!(v.entries[0].password.as_deref(), Some("only-a-password"));
    }

    #[test]
    fn garbage_json_line_reports_line_number() {
        let err = read("not json\n").unwrap_err();
        assert!(err.contains("line 1"), "{err}");
    }
}
