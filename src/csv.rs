//! RFC 4180 CSV reader used for Bitwarden CSV imports.
//!
//! Handles quoted fields, embedded commas, doubled quotes, embedded newlines
//! (multi-line notes are common in real exports) and both LF and CRLF line
//! endings. Rejects structurally broken rows instead of guessing — a
//! misaligned column in a password file is not something to paper over.

/// Parse an entire CSV document into rows of fields.
pub fn parse(input: &str) -> Result<Vec<Vec<String>>, String> {
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;
    let mut field_started = false;
    let mut line = 1usize;

    while let Some(ch) = chars.next() {
        if in_quotes {
            match ch {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                    }
                }
                '\n' => {
                    line += 1;
                    field.push('\n');
                }
                c => field.push(c),
            }
            continue;
        }
        match ch {
            '"' => {
                if field.is_empty() && !field_started {
                    in_quotes = true;
                    field_started = true;
                } else {
                    return Err(format!("line {line}: stray quote inside unquoted field"));
                }
            }
            ',' => {
                row.push(std::mem::take(&mut field));
                field_started = false;
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    continue; // handled by the '\n' arm
                }
                return Err(format!("line {line}: bare carriage return"));
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                field_started = false;
                rows.push(std::mem::take(&mut row));
                line += 1;
            }
            c => {
                field.push(c);
                field_started = true;
            }
        }
    }
    if in_quotes {
        return Err(format!("line {line}: unterminated quoted field"));
    }
    if field_started || !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_rows_split_on_commas_and_newlines() {
        let rows = parse("a,b,c\nd,e,f\n").unwrap();
        assert_eq!(rows, vec![vec!["a", "b", "c"], vec!["d", "e", "f"]]);
    }

    #[test]
    fn quoted_field_keeps_commas_quotes_and_newlines() {
        // A realistic note: multi-line, with a doubled quote and a comma.
        let rows = parse("name,notes\nbox,\"line1, still line1\nline2 \"\"quoted\"\"\"\n").unwrap();
        assert_eq!(rows[1][1], "line1, still line1\nline2 \"quoted\"");
    }

    #[test]
    fn crlf_and_missing_final_newline_are_accepted() {
        assert_eq!(
            parse("a,b\r\nc,d\r\n").unwrap(),
            vec![vec!["a", "b"], vec!["c", "d"]]
        );
        assert_eq!(
            parse("a,b\nc,d").unwrap(),
            vec![vec!["a", "b"], vec!["c", "d"]]
        );
    }

    #[test]
    fn empty_fields_survive() {
        let rows = parse("a,,c\n,,\n").unwrap();
        assert_eq!(rows[0], vec!["a", "", "c"]);
        assert_eq!(rows[1], vec!["", "", ""]);
    }

    #[test]
    fn broken_quoting_is_an_error_not_a_guess() {
        assert!(parse("a,\"broken\n").is_err(), "unterminated quote");
        assert!(parse("a,b\"c\n").is_err(), "stray quote mid-field");
    }
}
