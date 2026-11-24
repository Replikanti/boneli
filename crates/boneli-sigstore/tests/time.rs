//! RFC 3339 as `trusted_root.json` writes it, and the rounding of window
//! bounds to milliseconds.

use boneli_sigstore::time::parse;

#[test]
fn accepted_forms() {
    let t = parse("2021-01-12T11:53:27Z").expect("Rekor v1 start");
    assert_eq!((t.secs(), t.nanos()), (1_610_452_407, 0));
    let t = parse("2022-12-31T23:59:59.999Z").expect("Fulcio end");
    assert_eq!((t.secs(), t.nanos()), (1_672_531_199, 999_000_000));
    assert_eq!(parse("1970-01-01T00:00:00Z").expect("epoch").secs(), 0);
    assert_eq!(
        parse("2024-02-29T00:00:00Z").expect("leap day").secs(),
        1_709_164_800
    );
    assert_eq!(
        parse("2000-02-29T12:00:00Z").expect("leap 2000").secs(),
        951_825_600
    );
    assert_eq!(
        parse("2026-11-20T00:00:00.123456789Z").expect("ns").nanos(),
        123_456_789
    );
    assert_eq!(
        parse("9999-12-31T23:59:59Z").expect("max").secs(),
        253_402_300_799
    );
}

#[test]
fn refused_forms() {
    for text in [
        "",
        "2021-01-12T11:53:27",
        "2021-01-12T11:53:27z",
        "2021-01-12t11:53:27Z",
        "2021-01-12 11:53:27Z",
        "2021-01-12T11:53:27+00:00",
        "2021-01-12T11:53:27.Z",
        "2021-01-12T11:53:27.1234567890Z",
        "2021-01-12T11:53:60Z",
        "2021-01-12T24:00:00Z",
        "2021-01-12T11:60:00Z",
        "2021-02-29T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2021-13-01T00:00:00Z",
        "2021-00-01T00:00:00Z",
        "2021-04-31T00:00:00Z",
        "2021-01-00T00:00:00Z",
        "1969-12-31T23:59:59Z",
        "+2021-01-12T11:53:27Z",
        "2021-1-12T11:53:27Z",
        "２０２１-01-12T11:53:27Z",
        "2021-01-12T11:53:27.5\u{200b}Z",
    ] {
        assert_eq!(parse(text), None, "{text:?}");
    }
}

#[test]
fn fractional_window_rounding() {
    // A start of …:15.5Z admits 15,500 ms on, so 16 s but not 15 s.
    let start = parse("2026-01-01T00:00:15.5Z").expect("start");
    let base = parse("2026-01-01T00:00:00Z").expect("base").secs() * 1_000;
    assert_eq!(start.start_ms(), base + 15_500);
    assert!(base + 15_000 < start.start_ms());
    assert!(base + 16_000 >= start.start_ms());
    // An end of …:59.999Z admits 59 s, not 60 s.
    let end = parse("2026-01-01T00:00:59.999Z").expect("end");
    assert_eq!(end.end_ms(), base + 59_999);
    assert!(base + 59_000 <= end.end_ms());
    assert!(base + 60_000 > end.end_ms());
    // Below a millisecond: a start rounds up, an end down.
    let fine = parse("2026-01-01T00:00:01.0000001Z").expect("fine");
    assert_eq!(fine.start_ms(), base + 1_001);
    assert_eq!(fine.end_ms(), base + 1_000);
    let whole = parse("2026-01-01T00:00:01.000Z").expect("whole");
    assert_eq!(
        (whole.start_ms(), whole.end_ms()),
        (base + 1_000, base + 1_000)
    );
}
