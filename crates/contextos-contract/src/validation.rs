//! Shared contract validation: identifiers, digests and exact UTC contract time.
//!
//! Reference evaluators never read the clock. Every time-dependent check receives an
//! explicit, validated `evaluation_time`, and validity windows are half-open
//! `[not_before, expires_at)`.

use std::cmp::Ordering;

/// Maximum UTF-16 length of a contract identifier.
pub const MAX_IDENTIFIER_UTF16: usize = 512;
/// Maximum number of Unicode code points in a contract identifier.
pub const MAX_IDENTIFIER_CHARS: usize = 256;

/// Non-empty identifier within both the UTF-16 and code-point bounds of the schemas.
pub fn is_contract_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_IDENTIFIER_CHARS
        && value.encode_utf16().count() <= MAX_IDENTIFIER_UTF16
}

/// A parsed `YYYY-MM-DDTHH:MM:SS[.fraction]Z` contract timestamp.
///
/// Leap-second labels (`:60`) are rejected: exact ordering across a leap second needs
/// an external leap table and is the job of a separate time-scale adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractTime<'a> {
    whole: &'a str,
    fraction: &'a str,
}

impl<'a> ContractTime<'a> {
    pub fn parse(value: &'a str) -> Option<Self> {
        if value.len() > 256 || !value.is_ascii() {
            return None;
        }
        let bytes = value.as_bytes();
        if bytes.len() < 20 || bytes[bytes.len() - 1] != b'Z' {
            return None;
        }
        let shape_ok = bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
                .iter()
                .all(|&i| bytes[i].is_ascii_digit());
        if !shape_ok {
            return None;
        }
        let fraction = if bytes.len() == 20 {
            ""
        } else {
            let tail = &value[19..value.len() - 1];
            let digits = tail.strip_prefix('.')?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            digits
        };
        let num = |range: std::ops::Range<usize>| value[range].parse::<u32>().ok();
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
        if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        if day < 1 || day > days_in_month(year, month) {
            return None;
        }
        Some(Self {
            whole: &value[..19],
            fraction,
        })
    }

    /// Seconds since 0000-01-01T00:00:00Z in the proleptic Gregorian calendar.
    fn whole_seconds(&self) -> i64 {
        let n = |range: std::ops::Range<usize>| i64::from(self.whole[range].parse::<u32>().unwrap_or(0));
        let (year, month, day) = (n(0..4), n(5..7), n(8..10));
        let days = days_from_civil(year, month, day);
        days * 86_400 + n(11..13) * 3_600 + n(14..16) * 60 + n(17..19)
    }
}

impl Ord for ContractTime<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.whole.cmp(other.whole).then_with(|| {
            let width = self.fraction.len().max(other.fraction.len());
            let pad = |f: &str| format!("{f:0<width$}");
            pad(self.fraction).cmp(&pad(other.fraction))
        })
    }
}

impl PartialOrd for ContractTime<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn is_leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's days_from_civil, shifted so that only relative values matter.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Formats microseconds since the Unix epoch as a contract timestamp
/// (`YYYY-MM-DDTHH:MM:SS.ffffffZ`). Runtime clocks use this; the kernel never does.
pub fn format_unix_micros(micros: i64) -> String {
    let seconds = micros.div_euclid(1_000_000);
    let fraction = micros.rem_euclid(1_000_000);
    // 1970-01-01 relative to the epoch used by days_from_civil.
    let epoch_days = days_from_civil(1970, 1, 1);
    let days = epoch_days + seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{fraction:06}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

pub fn is_contract_timestamp(value: &str) -> bool {
    ContractTime::parse(value).is_some()
}

/// Exact comparison of two contract timestamps; `None` if either is invalid.
pub fn compare_contract_times(left: &str, right: &str) -> Option<Ordering> {
    Some(ContractTime::parse(left)?.cmp(&ContractTime::parse(right)?))
}

/// True when `start < end` and `start <= time < end`.
pub fn is_within_contract_interval(time: &str, start: &str, end: &str) -> bool {
    matches!(
        (
            compare_contract_times(start, end),
            compare_contract_times(time, start),
            compare_contract_times(time, end),
        ),
        (
            Some(Ordering::Less),
            Some(Ordering::Equal | Ordering::Greater),
            Some(Ordering::Less)
        )
    )
}

/// True when `0 <= time - observed <= maximum_seconds`, computed exactly over whole
/// seconds plus arbitrary-precision fractional digits.
pub fn age_within_limit(time: &str, observed: &str, maximum_seconds: u64) -> bool {
    const MAX_SAFE: u64 = (1 << 53) - 1;
    let (Some(t), Some(o)) = (ContractTime::parse(time), ContractTime::parse(observed)) else {
        return false;
    };
    if maximum_seconds > MAX_SAFE {
        return false;
    }
    let whole = t.whole_seconds() - o.whole_seconds();
    let width = t.fraction.len().max(o.fraction.len());
    let (ft, fo) = (format!("{:0<width$}", t.fraction), format!("{:0<width$}", o.fraction));
    // elapsed = whole + (ft - fo) / 10^width, with |ft - fo| / 10^width < 1.
    let non_negative = whole > 0 || (whole == 0 && ft >= fo);
    let max = i64::try_from(maximum_seconds).unwrap_or(i64::MAX);
    let within_max = whole < max || (whole == max && ft <= fo);
    non_negative && within_max
}

/// Adds whole seconds while preserving the original fractional digits exactly.
/// Returns `None` for invalid input or a result after `9999-12-31T23:59:59Z`.
pub fn add_contract_seconds(time: &str, seconds: u64) -> Option<String> {
    const MAX_SAFE: u64 = (1 << 53) - 1;
    if seconds > MAX_SAFE {
        return None;
    }
    let parsed = ContractTime::parse(time)?;
    let total = parsed.whole_seconds().checked_add(i64::try_from(seconds).ok()?)?;
    let max = ContractTime::parse("9999-12-31T23:59:59Z")?.whole_seconds();
    if total > max {
        return None;
    }
    let (days, rem) = (total.div_euclid(86_400), total.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    let fraction = &time[19..time.len() - 1];
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{fraction}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_bounded_by_code_points_and_utf16() {
        assert!(!is_contract_identifier(""));
        assert!(is_contract_identifier(&"a".repeat(256)));
        assert!(!is_contract_identifier(&"a".repeat(257)));
        // 256 astral characters are 512 UTF-16 units: still valid.
        assert!(is_contract_identifier(&"\u{1f600}".repeat(256)));
    }

    #[test]
    fn timestamps_validate_calendar_and_reject_leap_seconds() {
        assert!(is_contract_timestamp("2024-02-29T23:59:59Z"));
        assert!(is_contract_timestamp("2026-10-20T10:00:00.123456789Z"));
        assert!(!is_contract_timestamp("2023-02-29T00:00:00Z"));
        assert!(!is_contract_timestamp("2026-10-20T10:00:60Z"));
        assert!(!is_contract_timestamp("2026-10-20T10:00:00+00:00"));
        assert!(!is_contract_timestamp("2026-10-20T10:00:00.Z"));
        assert!(!is_contract_timestamp("2026-13-01T00:00:00Z"));
    }

    #[test]
    fn comparison_pads_fractions() {
        assert_eq!(
            compare_contract_times("2026-01-01T00:00:00.5Z", "2026-01-01T00:00:00.50Z"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare_contract_times("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000001Z"),
            Some(Ordering::Less)
        );
        assert_eq!(compare_contract_times("bad", "2026-01-01T00:00:00Z"), None);
    }

    #[test]
    fn intervals_are_half_open() {
        let (start, end) = ("2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z");
        assert!(is_within_contract_interval(start, start, end));
        assert!(!is_within_contract_interval(end, start, end));
        assert!(!is_within_contract_interval(start, end, start));
    }

    #[test]
    fn unix_micros_format() {
        assert_eq!(format_unix_micros(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(format_unix_micros(1_792_489_200_123_456), "2026-10-20T09:40:00.123456Z");
        assert!(is_contract_timestamp(&format_unix_micros(1_792_489_200_123_456)));
    }

    #[test]
    fn age_is_exact_with_fractions() {
        assert!(age_within_limit("2026-01-01T00:00:10Z", "2026-01-01T00:00:00Z", 10));
        assert!(!age_within_limit(
            "2026-01-01T00:00:10.000000001Z",
            "2026-01-01T00:00:00Z",
            10
        ));
        assert!(age_within_limit("2026-01-01T00:00:10.5Z", "2026-01-01T00:00:00.5Z", 10));
        assert!(!age_within_limit("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.1Z", 10));
        assert!(age_within_limit("2026-01-01T00:00:00.1Z", "2026-01-01T00:00:00.1Z", 0));
    }

    #[test]
    fn adding_seconds_crosses_calendar_boundaries() {
        assert_eq!(
            add_contract_seconds("2024-02-28T23:59:59.250Z", 1).unwrap(),
            "2024-02-29T00:00:00.250Z"
        );
        assert_eq!(
            add_contract_seconds("2025-12-31T23:00:00Z", 3_600).unwrap(),
            "2026-01-01T00:00:00Z"
        );
        assert_eq!(add_contract_seconds("9999-12-31T23:59:59Z", 1), None);
    }
}
