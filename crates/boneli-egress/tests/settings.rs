//! The production settings are exactly the numbers ADR-006 derives (D5,
//! D7, D9), and zero values are refused.

use std::time::Duration;

use boneli_egress::Settings;
use boneli_http::{Limits, ServerLimits};

#[test]
fn production_settings_match_adr_006() {
    let s = Settings::production();
    let server = s.server();
    assert_eq!(server.http().max_head_bytes(), 8192);
    assert_eq!(server.http().max_headers(), 32);
    assert_eq!(server.http().max_body_bytes(), 1);
    assert_eq!(server.max_connections(), 64);
    assert_eq!(server.idle_timeout(), Duration::from_secs(10));
    assert_eq!(server.request_timeout(), Duration::from_secs(10));
    assert_eq!(server.write_timeout(), Duration::from_secs(10));
    assert_eq!(s.connect_attempt(), Duration::from_secs(10));
    assert_eq!(s.connect_total(), Duration::from_secs(30));
    assert_eq!(s.tunnel_idle(), Duration::from_secs(660));
    assert_eq!(s.relay_buffer(), 16 * 1024);
}

#[test]
fn settings_reject_zero_values() {
    let one = Duration::from_millis(1);
    let http = Limits::new(1, 1, 1).expect("limits");
    let server = ServerLimits::new(http, 1, one, one, one).expect("limits");
    assert!(Settings::new(server, one, one, one, 1).is_ok());
    assert!(Settings::new(server, Duration::ZERO, one, one, 1).is_err());
    assert!(Settings::new(server, one, Duration::ZERO, one, 1).is_err());
    assert!(Settings::new(server, one, one, Duration::ZERO, 1).is_err());
    assert!(Settings::new(server, one, one, one, 0).is_err());
}
