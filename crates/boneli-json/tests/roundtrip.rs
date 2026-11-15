//! Serializing and parsing again gives back the same value, and the
//! serialized form is a fixed point (ADR-008, D3 and D7).

mod common;

use boneli_json::{MAX_DEPTH, Value, parse, to_vec};
use common::{Rng, built_arrays, built_objects, corpus, gen_value, harness_limits};

fn round_trip(v: &Value) {
    let lim = harness_limits();
    let bytes = to_vec(v).expect("serializable");
    let back = parse(&bytes, &lim)
        .unwrap_or_else(|e| panic!("{e} in {}", String::from_utf8_lossy(&bytes)));
    assert_eq!(&back, v);
    assert_eq!(to_vec(&back).expect("serializable"), bytes);
}

#[test]
fn suite_values_round_trip() {
    let lim = harness_limits();
    let mut checked = 0;
    for (_, bytes) in corpus() {
        if let Ok(v) = parse(&bytes, &lim) {
            round_trip(&v);
            checked += 1;
        }
    }
    // 93 accepted y_ files and 11 accepted i_ files.
    assert_eq!(checked, 104);
}

#[test]
fn generated_values_round_trip() {
    let mut rng = Rng::new(0x5eed_0b0e_115e_0029);
    let mut deepest = 0;
    for _ in 0..10_000 {
        let v = gen_value(&mut rng, 8);
        let (depth, _) = common::shape(&v);
        deepest = deepest.max(depth);
        round_trip(&v);
    }
    assert!(deepest >= 4, "the generator stays shallow: {deepest}");
}

#[test]
fn max_depth_value_round_trips() {
    round_trip(&built_arrays(MAX_DEPTH));
    round_trip(&built_objects(MAX_DEPTH));
}
