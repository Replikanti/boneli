//! RFC 3339 timestamps of the one form `trusted_root.json` writes
//! (protobuf's `Timestamp` in JSON): `YYYY-MM-DDTHH:MM:SS[.f]Z` with one
//! to nine fraction digits, in UTC, at or after the Unix epoch. No offset
//! other than `Z`, no lower-case `t` or `z`, no leap second (`:60`), no
//! space instead of `T`.
//!
//! Windows are compared in milliseconds. A fraction finer than a
//! millisecond rounds a window's start up and its end down, so a window
//! never admits a time outside the one written (ADR-029, limits):
//! `…:15.5Z` as a start admits 15,500 ms and later, which for Rekor's
//! whole-second integrated times means 16 s on; `…:59.999Z` as an end
//! admits up to 59,999 ms, so 59 s but not 60 s.

/// A parsed timestamp: whole seconds since the Unix epoch and the
/// nanoseconds of the fraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    secs: u64,
    nanos: u32,
}

impl Timestamp {
    /// Whole seconds since the Unix epoch.
    pub fn secs(&self) -> u64 {
        self.secs
    }

    /// The fraction, in nanoseconds.
    pub fn nanos(&self) -> u32 {
        self.nanos
    }

    /// Milliseconds, a sub-millisecond fraction rounded up: the first
    /// millisecond a window starting here admits.
    pub fn start_ms(&self) -> u64 {
        self.secs * 1_000 + u64::from(self.nanos.div_ceil(1_000_000))
    }

    /// Milliseconds, a sub-millisecond fraction rounded down: the last
    /// millisecond a window ending here admits.
    pub fn end_ms(&self) -> u64 {
        self.secs * 1_000 + u64::from(self.nanos / 1_000_000)
    }
}

/// Parses `text`, or `None` when it is not of the one accepted form or
/// names no real time (a 30 February, an hour 24) or one before 1970.
pub fn parse(text: &str) -> Option<Timestamp> {
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    if b[13] != b':' || b[16] != b':' || b[b.len() - 1] != b'Z' {
        return None;
    }
    let year = digits(&b[0..4])?;
    let month = digits(&b[5..7])?;
    let day = digits(&b[8..10])?;
    let hour = digits(&b[11..13])?;
    let minute = digits(&b[14..16])?;
    let second = digits(&b[17..19])?;
    let nanos = match &b[19..b.len() - 1] {
        [] => 0,
        [b'.', fraction @ ..] if (1..=9).contains(&fraction.len()) => {
            let value = digits(fraction)?;
            // Scale to nanoseconds: nine digits in all.
            value * 10u64.pow(9 - fraction.len() as u32)
        }
        _ => return None,
    };
    if year < 1970 || !(1..=12).contains(&month) || day == 0 || day > days_in(year, month) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(Timestamp {
        secs: days * 86_400 + hour * 3_600 + minute * 60 + second,
        nanos: nanos as u32,
    })
}

/// The value of a run of ASCII digits, or `None` for any other byte.
/// At most nine digits are ever passed, so it cannot overflow.
fn digits(bytes: &[u8]) -> Option<u64> {
    bytes.iter().try_fold(0u64, |acc, &c| {
        c.is_ascii_digit().then(|| acc * 10 + u64::from(c - b'0'))
    })
}

fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in(year: u64, month: u64) -> u64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to the date, for years from 1970 on.
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let leaps = |y: u64| y / 4 - y / 100 + y / 400;
    let years = year - 1970;
    let mut days = years * 365 + leaps(year - 1) - leaps(1969);
    for m in 1..month {
        days += days_in(year, m);
    }
    days + day - 1
}
