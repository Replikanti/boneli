#!/usr/bin/env cargo /*
/// Takes a lock behind a shebang line.
pub fn take(file: &std::fs::File) -> std::io::Result<()> {
    file.lock()
}
// */
