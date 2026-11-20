//! The hosts(5) reader (ADR-022, D2): the file the resolver reads before
//! it asks any name server, as nss_files does, with no search list.

use std::io::{self, BufRead};
use std::net::IpAddr;
use std::time::Instant;

use crate::dial::time_left;

/// The addresses of every line of `reader` that names `name`, as its
/// canonical name or an alias (ASCII case-insensitively), in file order.
///
/// Fields are split on ASCII whitespace as glibc's `isspace` splits them,
/// so a CR at the end of a line is whitespace; `#` starts a comment that
/// runs to the end of the line. A line whose address `IpAddr::from_str`
/// does not read (`127.1`, a zone such as `fe80::1%lo`) is skipped. The
/// deadline is checked before every line, so a huge file ends with
/// `TimedOut`; a deadline that has passed fails before the first line.
pub(crate) fn lookup_hosts(
    mut reader: impl BufRead,
    name: &str,
    deadline: Instant,
) -> io::Result<Vec<IpAddr>> {
    let mut found = Vec::new();
    let mut line = Vec::new();
    loop {
        time_left(deadline)?;
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(found);
        }
        let content = match line.iter().position(|&b| b == b'#') {
            Some(at) => line.get(..at).unwrap_or_default(),
            None => &line,
        };
        let mut fields = content
            .split(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r'))
            .filter(|f| !f.is_empty());
        let Some(address) = fields.next() else {
            continue;
        };
        let Some(ip) = std::str::from_utf8(address)
            .ok()
            .and_then(|a| a.parse::<IpAddr>().ok())
        else {
            continue;
        };
        if fields.any(|alias| alias.eq_ignore_ascii_case(name.as_bytes())) {
            found.push(ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, Read};
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    use super::lookup_hosts;

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().expect("ip")).collect()
    }

    fn lookup(text: &str, name: &str) -> Vec<IpAddr> {
        lookup_hosts(text.as_bytes(), name, far()).expect("hosts")
    }

    #[test]
    fn hosts_match_names_and_aliases_case_insensitively() {
        let text = "192.0.2.1 Git.Corp.Example git mirror\n";
        assert_eq!(lookup(text, "git.corp.example"), ips(&["192.0.2.1"]));
        assert_eq!(lookup(text, "git"), ips(&["192.0.2.1"]));
        assert_eq!(lookup(text, "mirror"), ips(&["192.0.2.1"]));
        assert_eq!(lookup(text, "corp.example"), ips(&[]));
        // The address field is never a name.
        assert_eq!(lookup(text, "192.0.2.1"), ips(&[]));
    }

    #[test]
    fn hosts_comments_tabs_and_crlf() {
        let text = "# 192.0.2.9 git\n192.0.2.1\tgit\r\n192.0.2.2 other # git\n\
                    \t 192.0.2.3 \x0Bgit\x0C\r\n192.0.2.4 git#comment\n";
        assert_eq!(
            lookup(text, "git"),
            ips(&["192.0.2.1", "192.0.2.3", "192.0.2.4"])
        );
    }

    #[test]
    fn non_canonical_and_zoned_addresses_are_skipped() {
        let text = "127.1 git\nfe80::1%lo git\n0x7f000001 git\n2130706433 git\n::1 git\n";
        assert_eq!(lookup(text, "git"), ips(&["::1"]));
        // A line that is not UTF-8 is skipped, not an error.
        let bytes = b"\xff\xfe git\n192.0.2.1 git\n";
        assert_eq!(
            lookup_hosts(&bytes[..], "git", far()).expect("hosts"),
            ips(&["192.0.2.1"])
        );
    }

    #[test]
    fn every_matching_line_counts_in_file_order() {
        let text =
            "2001:db8::1 git\n192.0.2.1 git\n192.0.2.2 other\n192.0.2.1 git\n192.0.2.3 alias git";
        assert_eq!(
            lookup(text, "git"),
            ips(&["2001:db8::1", "192.0.2.1", "192.0.2.1", "192.0.2.3"])
        );
    }

    /// Lines that arrive 20 ms apart, without end.
    struct Slow;

    impl Read for Slow {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            unreachable!("read through BufRead")
        }
    }

    impl BufRead for Slow {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            std::thread::sleep(Duration::from_millis(20));
            Ok(b"192.0.2.1 other\n")
        }

        fn consume(&mut self, _: usize) {}
    }

    #[test]
    fn hosts_read_stops_at_the_deadline() {
        let start = Instant::now();
        let err =
            lookup_hosts(Slow, "git", start + Duration::from_millis(150)).expect_err("deadline");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(150), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        // A deadline that has passed reads nothing.
        let err =
            lookup_hosts("192.0.2.1 git\n".as_bytes(), "git", Instant::now()).expect_err("passed");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
