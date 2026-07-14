//! RFC 3339 <-> Unix-seconds conversion, std only, UTC.
//!
//! Bitwarden and KeePass exports carry RFC 3339 timestamps; 1PIF carries Unix
//! epoch seconds. vaultvert normalizes on Unix seconds internally and formats
//! back out per target. Uses Howard Hinnant's days-from-civil algorithm, so
//! it is exact over the entire representable range with no table lookups.

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn to_rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Parse an RFC 3339 timestamp (`Z` or `±hh:mm` offset, optional fractional
/// seconds which are truncated) into Unix seconds.
pub fn parse_rfc3339(s: &str) -> Result<i64, String> {
    let b = s.as_bytes();
    let err = || format!("invalid RFC 3339 timestamp '{s}'");
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't') {
        return Err(err());
    }
    let num = |range: std::ops::Range<usize>| -> Result<i64, String> {
        s.get(range)
            .and_then(|t| t.parse::<i64>().ok())
            .ok_or_else(err)
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=days_in_month(y, mo as u32) as i64).contains(&d) {
        return Err(err());
    }
    if h > 23 || mi > 59 || sec > 60 {
        return Err(err());
    }

    // Skip fractional seconds, then read the offset.
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err(err());
        }
    }
    let offset_secs: i64 = match b.get(i) {
        Some(b'Z') | Some(b'z') if i + 1 == b.len() => 0,
        Some(&sign @ (b'+' | b'-')) if i + 6 == b.len() && b[i + 3] == b':' => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            if oh > 23 || om > 59 {
                return Err(err());
            }
            let total = oh * 3600 + om * 60;
            if sign == b'-' {
                -total
            } else {
                total
            }
        }
        _ => return Err(err()),
    };

    let days = days_from_civil(y, mo as u32, d as u32);
    Ok(days * 86_400 + h * 3600 + mi * 60 + sec.min(59) - offset_secs)
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
    }
}

/// Days since 1970-01-01 for a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of `days_from_civil`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = ((mp + 2) % 12 + 1) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_timestamps_round_trip() {
        assert_eq!(to_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2026-07-13T09:30:00Z == 1783935000 (independent computation).
        assert_eq!(
            parse_rfc3339("2026-07-13T09:30:00Z").unwrap(),
            1_783_935_000
        );
        assert_eq!(to_rfc3339(1_783_935_000), "2026-07-13T09:30:00Z");
    }

    #[test]
    fn fractional_seconds_are_truncated() {
        // Bitwarden emits e.g. "2026-05-01T08:00:00.000Z".
        assert_eq!(
            parse_rfc3339("2026-05-01T08:00:00.123456Z").unwrap(),
            parse_rfc3339("2026-05-01T08:00:00Z").unwrap()
        );
    }

    #[test]
    fn numeric_offsets_shift_to_utc() {
        let plus = parse_rfc3339("2026-01-02T09:00:00+09:00").unwrap();
        let utc = parse_rfc3339("2026-01-02T00:00:00Z").unwrap();
        assert_eq!(plus, utc);
        let minus = parse_rfc3339("2026-01-01T19:00:00-05:00").unwrap();
        assert_eq!(minus, utc);
    }

    #[test]
    fn leap_day_is_valid_and_round_trips() {
        let t = parse_rfc3339("2024-02-29T12:00:00Z").unwrap();
        assert_eq!(to_rfc3339(t), "2024-02-29T12:00:00Z");
        // 2026 is not a leap year.
        assert!(parse_rfc3339("2026-02-29T12:00:00Z").is_err());
    }

    #[test]
    fn every_day_of_2026_round_trips() {
        // Exhaustive one-year sweep guards the civil-date math.
        let start = parse_rfc3339("2026-01-01T00:00:00Z").unwrap();
        for day in 0..365 {
            let t = start + day * 86_400;
            assert_eq!(parse_rfc3339(&to_rfc3339(t)).unwrap(), t);
        }
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in [
            "",
            "2026-13-01T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01 00:00:00Z",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00+9:00",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "accepted {bad:?}");
        }
    }
}
