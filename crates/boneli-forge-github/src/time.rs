//! Wall-clock time for the token cache (ADR-014, D5): the RFC 3339
//! `date-time` GitHub sends as `expires_at`, the civil-date arithmetic
//! behind it, and the [`WallClock`] seam the tests replace.
//!
//! The core has no clock (invariant 2); this adapter needs one, because a
//! JWT carries absolute times and an installation token expires at one.

use std::time::{SystemTime, UNIX_EPOCH};

/// Where the adapter reads the time. Seconds since the Unix epoch, or
/// `None` when the clock reads before 1970, which no JWT can carry.
pub trait WallClock: Send + Sync {
    /// The current Unix time in seconds.
    fn unix_seconds(&self) -> Option<u64>;
}

/// The system clock (`SystemTime`).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl WallClock for SystemClock {
    fn unix_seconds(&self) -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
    }
}

const DAY: i64 = 86_400;

/// Days from 1970-01-01 to the proleptic Gregorian date `year-month-day`
/// (H. Hinnant's `days_from_civil`). `month` is 1 to 12 and `day` 1 to 31;
/// the caller checks that the day exists in the month.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01, as `(year, month, day)`; the inverse
/// of [`days_from_civil`].
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month as u32, day as u32)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `secs` as an RFC 3339 `date-time` in UTC, `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_rfc3339(secs: u64) -> String {
    let secs = i64::try_from(secs).unwrap_or(i64::MAX);
    let (year, month, day) = civil_from_days(secs.div_euclid(DAY));
    let rest = secs.rem_euclid(DAY);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// The Unix time of an RFC 3339 `date-time` (section 5.6), or `None`.
///
/// Accepted: `YYYY-MM-DD`, `T` or `t`, `HH:MM:SS`, an optional fraction of
/// 1 to 9 digits (dropped), and `Z`, `z` or an offset `+HH:MM`/`-HH:MM`
/// with hours below 24, which is applied. Refused: any other form (a space
/// for `T`, no offset), a day the month does not have, a leap second
/// (`:60`; GitHub never sends one, and accepting it would need a table),
/// a year before 1970 and a result before the epoch.
pub fn parse_rfc3339(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    let digits = |from: usize, len: usize| -> Option<u32> {
        let part = b.get(from..from + len)?;
        part.iter().all(u8::is_ascii_digit).then(|| {
            part.iter()
                .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'))
        })
    };
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    let year = i64::from(digits(0, 4)?);
    if !(at(4, b'-') && at(7, b'-') && matches!(b.get(10), Some(b'T' | b't'))) {
        return None;
    }
    let (month, day) = (digits(5, 2)?, digits(8, 2)?);
    if !at(13, b':') || !at(16, b':') {
        return None;
    }
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    let valid = year >= 1970
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour < 24
        && minute < 60
        && second < 60;
    if !valid {
        return None;
    }
    let mut i = 19;
    if at(i, b'.') {
        let start = i + 1;
        i = start;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if !(1..=9).contains(&(i - start)) {
            return None;
        }
    }
    let offset = match b.get(i) {
        Some(b'Z' | b'z') if b.len() == i + 1 => 0,
        Some(sign @ (b'+' | b'-')) if b.len() == i + 6 && at(i + 3, b':') => {
            let (oh, om) = (digits(i + 1, 2)?, digits(i + 4, 2)?);
            if oh >= 24 || om >= 60 {
                return None;
            }
            let seconds = i64::from(oh * 3_600 + om * 60);
            if *sign == b'+' { seconds } else { -seconds }
        }
        _ => return None,
    };
    let local =
        days_from_civil(year, month, day) * DAY + i64::from(hour * 3_600 + minute * 60 + second);
    u64::try_from(local - offset).ok()
}
