//! The hybrid post-quantum key exchange X25519MLKEM768 for the client
//! (RFC 10024, section 4; ADR-016): ML-KEM-768 (FIPS 203) from the
//! pure-Rust `ml-kem` crate next to ring's X25519, as one rustls key
//! exchange group.
//!
//! - The client's key share is the ML-KEM-768 encapsulation key followed
//!   by the X25519 share (section 4.1).
//! - The server's key share is the ML-KEM-768 ciphertext followed by the
//!   X25519 share (section 4.2).
//! - The shared secret is the ML-KEM shared secret followed by the X25519
//!   shared secret (section 4.3). TLS 1.3 feeds it into its key schedule,
//!   so the session is at least as strong as X25519 alone, whatever
//!   happens to ML-KEM.
//!
//! The group is client-only and TLS 1.3 only. It implements rustls'
//! `hybrid_component`, so the ClientHello carries the X25519 share a
//! second time on its own, and a server without the group picks X25519
//! with no extra round trip.

use ml_kem::array::Array;
use ml_kem::{Ciphertext, Decapsulate, DecapsulationKey768, KeyExport, MlKem768, Seed};
use rustls::crypto::ring::kx_group;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{NamedGroup, PeerMisbehaved, ProtocolVersion};
use zeroize::Zeroizing;

use crate::random::{RandomFailed, fill_random};

/// The ML-KEM-768 encapsulation key, the first part of the client's share
/// (RFC 10024, section 4.1; FIPS 203, table 3).
const EK_LEN: usize = 1184;
/// The ML-KEM-768 ciphertext, the first part of the server's share (RFC
/// 10024, section 4.2; FIPS 203, table 3).
const CT_LEN: usize = 1088;
/// An X25519 share and an X25519 shared secret (RFC 10024, sections 4.1
/// to 4.3; RFC 7748, section 5).
const X25519_LEN: usize = 32;
/// The client's share: encapsulation key, then X25519 (RFC 10024, section
/// 4.1).
const CLIENT_SHARE_LEN: usize = EK_LEN + X25519_LEN;
/// The server's share: ciphertext, then X25519 (RFC 10024, section 4.2).
const SERVER_SHARE_LEN: usize = CT_LEN + X25519_LEN;
/// The shared secret: the ML-KEM secret, then the X25519 secret (RFC
/// 10024, section 4.3).
const SECRET_LEN: usize = 32 + X25519_LEN;
/// The seed of ML-KEM key generation, d followed by z (FIPS 203,
/// algorithm 19).
const SEED_LEN: usize = 64;

/// X25519MLKEM768, codepoint 0x11EC (RFC 10024, section 7.1).
pub(crate) static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid;

/// The group. It holds no key material; each `start` makes a fresh key
/// pair.
struct Hybrid;

impl std::fmt::Debug for Hybrid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("X25519MLKEM768")
    }
}

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        start_with(fill_random)
    }

    /// The server role. The trait's default runs `start` and `complete`,
    /// which is right for Diffie-Hellman and wrong for a KEM, whose server
    /// encapsulates to the client's key; this crate is a client, so the
    /// role fails closed.
    fn start_and_complete(
        &self,
        _client_share: &[u8],
    ) -> Result<CompletedKeyExchange, rustls::Error> {
        Err(rustls::Error::General(
            "X25519MLKEM768 is client-only in boneli-https (ADR-016)".into(),
        ))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    /// TLS 1.3 only: RFC 10024 defines the group for TLS 1.3, whose
    /// transcript its security analysis relies on (section 6).
    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// Starts a key exchange with the ML-KEM seed from `fill`: the production
/// path passes `fill_random`, the known-answer tests a fixed seed, so both
/// run the same code. The seed is wiped once the key is made; a random
/// source that fails starts nothing.
fn start_with(
    fill: impl FnOnce(&mut [u8]) -> Result<(), RandomFailed>,
) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    fill(&mut seed[..]).map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
    // FIPS 203 ML-KEM.KeyGen_internal(d, z) with d || z from the seed; the
    // crate's own random key generation calls the same function.
    let mlkem = DecapsulationKey768::from_seed(Seed::from(*seed));
    drop(seed);
    let classical = kx_group::X25519.start()?;
    Ok(Box::new(ActiveHybrid::new(mlkem, classical)?))
}

/// The server's share as (ciphertext, X25519 share), or `None` when it is
/// not exactly 1120 bytes (RFC 10024, section 4.2).
fn split_server_share(share: &[u8]) -> Option<(&[u8], &[u8])> {
    if share.len() != SERVER_SHARE_LEN {
        return None;
    }
    Some(share.split_at(CT_LEN))
}

/// The ML-KEM decapsulation key where `ActiveHybrid` holds it, on the
/// heap inside rustls' `Box<dyn ActiveKeyExchange>`. `ml-kem`'s `zeroize`
/// feature wipes the key, d and z (the whole seed) included, in the copy
/// that is dropped and nowhere else: a key moved out of the box first is
/// wiped on the stack, and the heap copy stays in freed memory. Two guards
/// keep it in place. This type has a `Drop`, so the key can never be moved
/// out of it (E0509). The unit tests check that it is dropped at the
/// address it has in the box, on every path that ends a key exchange.
struct PinnedKey {
    key: DecapsulationKey768,
}

impl Drop for PinnedKey {
    /// The key itself is wiped by its own `Drop`, which runs right after
    /// this one, in the same place.
    fn drop(&mut self) {
        #[cfg(test)]
        tests::dropped_at(self as *const PinnedKey as usize);
    }
}

/// One key exchange in progress: the ML-KEM decapsulation key, pinned
/// (`PinnedKey`), the X25519 half and the share sent. No `Debug`: nothing
/// here is for logs.
struct ActiveHybrid {
    mlkem: PinnedKey,
    classical: Box<dyn ActiveKeyExchange>,
    share: Vec<u8>,
}

impl ActiveHybrid {
    /// The client's share is the encapsulation key, then the X25519 share
    /// (RFC 10024, section 4.1); a half of the wrong length is an error.
    fn new(
        mlkem: DecapsulationKey768,
        classical: Box<dyn ActiveKeyExchange>,
    ) -> Result<ActiveHybrid, rustls::Error> {
        let ek = mlkem.encapsulation_key().to_bytes();
        let x25519 = classical.pub_key();
        if ek.len() != EK_LEN || x25519.len() != X25519_LEN {
            return Err(rustls::Error::General(
                "X25519MLKEM768: a key share half has the wrong length".into(),
            ));
        }
        let mut share = Vec::with_capacity(CLIENT_SHARE_LEN);
        share.extend_from_slice(&ek);
        share.extend_from_slice(x25519);
        Ok(ActiveHybrid {
            mlkem: PinnedKey { key: mlkem },
            classical,
            share,
        })
    }
}

impl ActiveKeyExchange for ActiveHybrid {
    /// Completes both halves. A share of the wrong length, or an X25519
    /// share ring refuses (wrong length, or an all-zero result, as RFC
    /// 10024 section 4.3 requires), is an error, which rustls answers with
    /// an `illegal_parameter` alert (section 4.2). A ciphertext of the
    /// right length always decapsulates: a tampered one yields a secret
    /// the server does not have (FIPS 203 implicit rejection), so the
    /// handshake fails when its Finished does not verify.
    ///
    /// The key is used through the box and never moved out of it: only
    /// `classical` is moved, so the key is dropped and wiped where the box
    /// holds it (`PinnedKey`).
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let (ct, x25519) = split_server_share(peer).ok_or(PeerMisbehaved::InvalidKeyShare)?;
        let ct: Ciphertext<MlKem768> =
            Array::try_from(ct).map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        let k = Zeroizing::new(self.mlkem.key.decapsulate(&ct));
        let x = self.classical.complete(x25519)?;
        let mut secret = Vec::with_capacity(SECRET_LEN);
        secret.extend_from_slice(&k[..]);
        secret.extend_from_slice(x.secret_bytes());
        Ok(SharedSecret::from(secret))
    }

    /// The X25519 half on its own, sent as a second key share, so that a
    /// server without the hybrid picks X25519 without a retry.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, self.classical.pub_key()))
    }

    /// The server picked the X25519 share: only `classical` is moved out,
    /// and the ML-KEM half is dropped (and wiped) unused, in the box.
    fn complete_hybrid_component(
        self: Box<Self>,
        peer: &[u8],
    ) -> Result<SharedSecret, rustls::Error> {
        self.classical.complete(peer)
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        /// Where each `PinnedKey` of this test thread was dropped.
        static DROPS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn dropped_at(address: usize) {
        DROPS.with(|drops| drops.borrow_mut().push(address));
    }

    fn take_drops() -> Vec<usize> {
        DROPS.with(|drops| std::mem::take(&mut *drops.borrow_mut()))
    }

    /// The address of the key inside the box.
    fn slot(hybrid: &ActiveHybrid) -> usize {
        &hybrid.mlkem as *const PinnedKey as usize
    }

    /// Known-answer values: Wycheproof for ML-KEM-768, RFC 7748 for
    /// X25519; their sources are recorded in the file.
    const KAT: &str = include_str!("../tests/data/x25519mlkem768-kat.txt");

    /// The value `name` of the known-answer file, decoded.
    fn kat(name: &str) -> Vec<u8> {
        let hex = KAT
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (key, value) = line.split_once(" = ")?;
                (key == name).then_some(value)
            })
            .unwrap_or_else(|| panic!("no {name} in the known-answer file"));
        assert_eq!(hex.len() % 2, 0, "{name}: odd hex length");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
        [a, b].concat()
    }

    fn seed(test: &str) -> Seed {
        Seed::try_from(&kat(&format!("{test}.seed"))[..]).expect("64-byte seed")
    }

    fn invalid_key_share(result: Result<SharedSecret, rustls::Error>) -> bool {
        matches!(
            result,
            Err(rustls::Error::PeerMisbehaved(
                PeerMisbehaved::InvalidKeyShare
            ))
        )
    }

    /// A classical half with RFC 7748's values: Alice's share, and Alice's
    /// secret once it receives exactly Bob's share.
    struct FakeX25519 {
        public: Vec<u8>,
        expect_peer: Vec<u8>,
        secret: Vec<u8>,
    }

    impl FakeX25519 {
        fn rfc7748() -> Box<FakeX25519> {
            Box::new(FakeX25519 {
                public: kat("rfc7748.alice_public"),
                expect_peer: kat("rfc7748.bob_public"),
                secret: kat("rfc7748.shared"),
            })
        }
    }

    impl ActiveKeyExchange for FakeX25519 {
        fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
            assert_eq!(
                peer,
                &self.expect_peer[..],
                "the X25519 half got Bob's share"
            );
            Ok(SharedSecret::from(&self.secret[..]))
        }

        fn pub_key(&self) -> &[u8] {
            &self.public
        }

        fn group(&self) -> NamedGroup {
            NamedGroup::X25519
        }
    }

    /// The hybrid with the ML-KEM key of Wycheproof `test` and RFC 7748's
    /// X25519 values.
    fn kat_hybrid(test: &str) -> Box<ActiveHybrid> {
        let mlkem = DecapsulationKey768::from_seed(seed(test));
        Box::new(ActiveHybrid::new(mlkem, FakeX25519::rfc7748()).expect("hybrid"))
    }

    fn real() -> Box<dyn ActiveKeyExchange> {
        X25519MLKEM768.start().expect("start")
    }

    #[test]
    fn kat_client_share_is_ek_then_x25519() {
        let hybrid = kat_hybrid("tc2");
        let expected = concat(&kat("tc2.ek"), &kat("rfc7748.alice_public"));
        assert_eq!(expected.len(), 1216);
        assert_eq!(hybrid.pub_key(), &expected[..]);
    }

    #[test]
    fn kat_secret_is_mlkem_then_x25519() {
        let peer = concat(&kat("tc2.c"), &kat("rfc7748.bob_public"));
        let secret = kat_hybrid("tc2").complete(&peer).expect("complete");
        let expected = concat(&kat("tc2.K"), &kat("rfc7748.shared"));
        assert_eq!(expected.len(), 64);
        assert_eq!(secret.secret_bytes(), &expected[..]);
    }

    #[test]
    fn kat_with_ring_x25519_halves_in_place() {
        let tc2 = seed("tc2");
        let kx = start_with(|buf| {
            buf.copy_from_slice(&tc2);
            Ok(())
        })
        .expect("start");
        let share = kx.pub_key().to_vec();
        assert_eq!(share.len(), 1216);
        assert_eq!(&share[..1184], &kat("tc2.ek")[..]);
        let (group, component) = kx.hybrid_component().expect("component");
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(component, &share[1184..]);
        // The server's X25519 half, emulated with ring.
        let server = kx_group::X25519
            .start_and_complete(&share[1184..])
            .expect("server X25519");
        let peer = concat(&kat("tc2.c"), &server.pub_key);
        let secret = kx.complete(&peer).expect("complete");
        let expected = concat(&kat("tc2.K"), server.secret.secret_bytes());
        assert_eq!(secret.secret_bytes(), &expected[..]);
    }

    #[test]
    fn implicit_rejection_is_not_an_error() {
        // tcId 194 changes byte 0 of tcId 2's ciphertext; decapsulation
        // must return the implicit-rejection key, not an error.
        let peer = concat(&kat("tc194.c"), &kat("rfc7748.bob_public"));
        let secret = kat_hybrid("tc194").complete(&peer).expect("no error");
        assert_eq!(&secret.secret_bytes()[..32], &kat("tc194.K")[..]);
        assert_ne!(&secret.secret_bytes()[..32], &kat("tc2.K")[..]);
        assert_eq!(&secret.secret_bytes()[32..], &kat("rfc7748.shared")[..]);
    }

    #[test]
    fn server_share_lengths_other_than_1120_are_rejected() {
        for len in 0..=2 * 1120 + 64 {
            let share = vec![0x5a; len];
            assert_eq!(split_server_share(&share).is_some(), len == 1120, "{len}");
        }
        let mut share = vec![0xaa; 1088];
        share.extend_from_slice(&[0xbb; 32]);
        let (ct, x25519) = split_server_share(&share).expect("1120 bytes");
        assert_eq!(ct, &[0xaa; 1088][..]);
        assert_eq!(x25519, &[0xbb; 32][..]);
        for len in [0, 32, 1088, 1119, 1121, 1216, 2240] {
            assert!(
                invalid_key_share(real().complete(&vec![0x5a; len])),
                "{len}"
            );
        }
    }

    #[test]
    fn all_zero_x25519_part_is_rejected() {
        // u = 0 and u = 1 are low-order points: X25519 gives all zeros,
        // which ring refuses (RFC 10024, section 4.3; RFC 7748, section 6.1).
        let mut one = [0u8; 32];
        one[0] = 1;
        for x25519 in [[0u8; 32], one] {
            let peer = concat(&kat("tc2.c"), &x25519);
            assert!(invalid_key_share(real().complete(&peer)), "{x25519:?}");
        }
    }

    #[test]
    fn classical_completion_rejects_hybrid_length() {
        let peer = concat(&kat("tc2.c"), &kat("rfc7748.bob_public"));
        assert!(invalid_key_share(real().complete_hybrid_component(&peer)));
    }

    #[test]
    fn hybrid_component_is_the_x25519_share() {
        let kx = real();
        let (group, component) = kx.hybrid_component().expect("component");
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(component.len(), 32);
        assert_eq!(component, &kx.pub_key()[1184..]);
        assert_eq!(kx.group(), NamedGroup::X25519MLKEM768);
        assert_eq!(kx.ffdhe_group(), None);
    }

    #[test]
    fn group_is_tls13_only() {
        assert!(X25519MLKEM768.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!X25519MLKEM768.usable_for_version(ProtocolVersion::TLSv1_2));
        assert_eq!(X25519MLKEM768.ffdhe_group(), None);
        assert!(!X25519MLKEM768.fips());
        assert_eq!(X25519MLKEM768.name(), NamedGroup::X25519MLKEM768);
        assert_eq!(u16::from(X25519MLKEM768.name()), 0x11ec);
    }

    #[test]
    fn server_role_is_refused() {
        let client_share = concat(&kat("tc2.ek"), &kat("rfc7748.alice_public"));
        let result = X25519MLKEM768.start_and_complete(&client_share);
        assert!(
            matches!(&result, Err(rustls::Error::General(m)) if m.contains("client-only")),
            "{:?}",
            result.map(|done| done.pub_key.len())
        );
    }

    #[test]
    fn random_failure_fails_start() {
        let result = start_with(|_| Err(RandomFailed));
        assert!(
            matches!(result, Err(rustls::Error::FailedToGetRandomBytes)),
            "{:?}",
            result.map(|kx| kx.pub_key().len())
        );
    }

    #[test]
    fn fresh_keys_per_start() {
        let (a, b) = (real(), real());
        assert_ne!(&a.pub_key()[..1184], &b.pub_key()[..1184], "ML-KEM half");
        assert_ne!(&a.pub_key()[1184..], &b.pub_key()[1184..], "X25519 half");
    }

    #[test]
    fn key_is_dropped_in_place() {
        // Each path that ends a key exchange must drop the key where the
        // box holds it, so that `ml-kem` wipes that copy; a key moved out
        // of the box first is dropped somewhere else.
        let good = concat(&kat("tc2.c"), &kat("rfc7748.bob_public"));
        let zero_x25519 = concat(&kat("tc2.c"), &[0u8; 32]);
        let ring_hybrid = || {
            let mlkem = DecapsulationKey768::from_seed(seed("tc2"));
            let classical = kx_group::X25519.start().expect("X25519");
            Box::new(ActiveHybrid::new(mlkem, classical).expect("hybrid"))
        };
        type End = Box<dyn Fn(Box<ActiveHybrid>) -> bool>;
        let cases: Vec<(&str, Box<ActiveHybrid>, End)> = vec![
            (
                "complete",
                kat_hybrid("tc2"),
                Box::new(move |h| h.complete(&good).is_ok()),
            ),
            (
                "complete, wrong length",
                kat_hybrid("tc2"),
                Box::new(|h| invalid_key_share(h.complete(&[0x5a; 1119]))),
            ),
            (
                "complete, all-zero X25519",
                ring_hybrid(),
                Box::new(move |h| invalid_key_share(h.complete(&zero_x25519))),
            ),
            (
                "complete_hybrid_component",
                kat_hybrid("tc2"),
                Box::new(|h| {
                    h.complete_hybrid_component(&kat("rfc7748.bob_public"))
                        .is_ok()
                }),
            ),
            (
                "dropped unused",
                kat_hybrid("tc2"),
                Box::new(|h| {
                    drop(h);
                    true
                }),
            ),
        ];
        for (name, hybrid, end) in cases {
            take_drops();
            let address = slot(&hybrid);
            assert!(end(hybrid), "{name}: the expected result");
            assert_eq!(take_drops(), [address], "{name}: dropped once, in the box");
        }
    }

    #[test]
    fn debug_prints_only_the_name() {
        assert_eq!(format!("{X25519MLKEM768:?}"), "X25519MLKEM768");
    }
}
