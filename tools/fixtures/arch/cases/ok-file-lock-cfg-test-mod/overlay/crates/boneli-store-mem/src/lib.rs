//! Fixture crate.
#![doc(test(attr(forbid(unsafe_code))))]

/// A value.
pub fn value() -> u8 {
    1
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn locks() {
        let brace = "}";
        let file = std::fs::File::open("Cargo.toml").unwrap();
        file.lock().unwrap();
        file.unlock().unwrap();
        assert_eq!(brace, '}'.to_string());
    }
}
