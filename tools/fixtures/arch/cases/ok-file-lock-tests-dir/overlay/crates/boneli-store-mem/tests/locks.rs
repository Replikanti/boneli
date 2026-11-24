//! Integration test.

#[test]
fn locks() {
    let file = std::fs::File::open("Cargo.toml").expect("open");
    file.lock().expect("lock");
    std::fs::File::unlock(&file).expect("unlock");
}
