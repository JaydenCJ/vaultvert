//! Format registry: names, aliases, content sniffing and codec dispatch.

use crate::model::Vault;
use crate::report::Report;
use crate::{bitwarden, keepass, onepassword};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    BitwardenJson,
    BitwardenCsv,
    OnePif,
    KeepassXml,
}

pub const ALL: [Format; 4] = [
    Format::BitwardenJson,
    Format::BitwardenCsv,
    Format::OnePif,
    Format::KeepassXml,
];

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::BitwardenJson => "bitwarden-json",
            Format::BitwardenCsv => "bitwarden-csv",
            Format::OnePif => "1pif",
            Format::KeepassXml => "keepass-xml",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Format::BitwardenJson => "Bitwarden unencrypted .json export",
            Format::BitwardenCsv => "Bitwarden .csv export (no timestamps or item types)",
            Format::OnePif => "1Password interchange format (.1pif)",
            Format::KeepassXml => "KeePass 2.x XML export (.xml)",
        }
    }

    pub fn can_write(self) -> bool {
        // CSV is the lossy format this tool exists to replace; refusing to
        // write it is a feature, stated in the README.
        self != Format::BitwardenCsv
    }

    pub fn from_name(name: &str) -> Result<Format, String> {
        match name.to_lowercase().as_str() {
            "bitwarden" | "bitwarden-json" | "bw" | "json" => Ok(Format::BitwardenJson),
            "bitwarden-csv" | "csv" => Ok(Format::BitwardenCsv),
            "1password" | "1pif" | "onepassword" | "op" => Ok(Format::OnePif),
            "keepass" | "keepass-xml" | "kdbx-xml" | "kp" | "xml" => Ok(Format::KeepassXml),
            other => Err(format!(
                "unknown format '{other}' (expected one of: bitwarden-json, bitwarden-csv, 1pif, keepass-xml)"
            )),
        }
    }

    /// Pick a default target format from an output file extension.
    pub fn from_extension(path: &str) -> Option<Format> {
        let ext = path.rsplit_once('.').map(|(_, e)| e.to_lowercase())?;
        match ext.as_str() {
            "json" => Some(Format::BitwardenJson),
            "1pif" => Some(Format::OnePif),
            "xml" => Some(Format::KeepassXml),
            _ => None,
        }
    }

    pub fn read(self, text: &str) -> Result<(Vault, Vec<String>), String> {
        match self {
            Format::BitwardenJson => bitwarden::read_json(text).map(|v| (v, Vec::new())),
            Format::BitwardenCsv => bitwarden::read_csv(text).map(|v| (v, Vec::new())),
            Format::OnePif => onepassword::read(text),
            Format::KeepassXml => keepass::read(text),
        }
    }

    pub fn write(self, vault: &Vault, rep: &mut Report) -> Result<String, String> {
        match self {
            Format::BitwardenJson => Ok(bitwarden::write_json(vault, rep)),
            Format::OnePif => Ok(onepassword::write(vault, rep)),
            Format::KeepassXml => Ok(keepass::write(vault, rep)),
            Format::BitwardenCsv => Err(
                "refusing to write CSV: it cannot carry item types, timestamps, \
                 hidden-field flags or TOTP secrets losslessly. Pick bitwarden-json, \
                 1pif or keepass-xml."
                    .into(),
            ),
        }
    }
}

/// Sniff the format from file content. Extension hints are deliberately
/// secondary: people rename exports all the time.
pub fn sniff(text: &str, path: &str) -> Result<Format, String> {
    let head = text.trim_start();
    if text.contains(onepassword::SEPARATOR) {
        return Ok(Format::OnePif);
    }
    if head.starts_with('<') {
        if text.contains("<KeePassFile") {
            return Ok(Format::KeepassXml);
        }
        return Err(format!("'{path}' is XML but not a KeePass 2.x export"));
    }
    if head.starts_with('{') {
        if head.contains("\"items\"") {
            return Ok(Format::BitwardenJson);
        }
        return Err(format!(
            "'{path}' is JSON but has no \"items\" array — not a Bitwarden export \
             (encrypted 1Password .1pux archives are not supported; export .1pif instead)"
        ));
    }
    let first_line = head.lines().next().unwrap_or("");
    if first_line.contains("login_username") || first_line.contains("login_uri") {
        return Ok(Format::BitwardenCsv);
    }
    Err(format!(
        "cannot detect the format of '{path}'; pass --from bitwarden-json|bitwarden-csv|1pif|keepass-xml"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_each_supported_format() {
        assert_eq!(
            sniff("{\"encrypted\": false, \"items\": []}", "v.json").unwrap(),
            Format::BitwardenJson
        );
        assert_eq!(
            sniff(
                &format!("{{\"uuid\":\"A\"}}\n{}\n", crate::onepassword::SEPARATOR),
                "d.1pif"
            )
            .unwrap(),
            Format::OnePif
        );
        assert_eq!(
            sniff(
                "<?xml version=\"1.0\"?>\n<KeePassFile></KeePassFile>",
                "d.xml"
            )
            .unwrap(),
            Format::KeepassXml
        );
        assert_eq!(
            sniff("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n", "e.csv").unwrap(),
            Format::BitwardenCsv
        );
    }

    #[test]
    fn sniff_ignores_misleading_extensions() {
        // A KeePass export renamed to .json must still be detected as XML.
        assert_eq!(
            sniff("<KeePassFile></KeePassFile>", "renamed.json").unwrap(),
            Format::KeepassXml
        );
    }

    #[test]
    fn sniff_rejects_unknown_content_with_guidance() {
        let err = sniff("hello world", "mystery.txt").unwrap_err();
        assert!(err.contains("--from"));
        // Non-Bitwarden JSON gets a pointer to the 1PIF escape hatch.
        let err = sniff("{\"accounts\": []}", "other.json").unwrap_err();
        assert!(err.contains("1pux"));
    }

    #[test]
    fn format_names_round_trip_and_aliases_resolve() {
        for f in ALL {
            assert_eq!(Format::from_name(f.name()).unwrap(), f);
        }
        assert_eq!(
            Format::from_name("BitWarden").unwrap(),
            Format::BitwardenJson
        );
        assert_eq!(Format::from_name("1password").unwrap(), Format::OnePif);
        assert_eq!(Format::from_name("keepass").unwrap(), Format::KeepassXml);
        assert!(Format::from_name("lastpass").is_err());
    }

    #[test]
    fn extension_defaults_map_to_writable_formats() {
        assert_eq!(
            Format::from_extension("out.json"),
            Some(Format::BitwardenJson)
        );
        assert_eq!(Format::from_extension("out.1PIF"), Some(Format::OnePif));
        assert_eq!(Format::from_extension("out.xml"), Some(Format::KeepassXml));
        assert_eq!(Format::from_extension("out.csv"), None);
        assert_eq!(Format::from_extension("noext"), None);
    }

    #[test]
    fn csv_writer_is_refused_with_explanation() {
        let err = Format::BitwardenCsv
            .write(&Vault::default(), &mut Report::default())
            .unwrap_err();
        assert!(err.contains("refusing"));
    }
}
