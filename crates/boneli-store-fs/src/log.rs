//! The run logs (ADR-012, D2, D4 and D5): `runs/<hex>.log`, named by the
//! SHA-256 of the run id, with the id in the header.
//!
//! Every operation holds the store's log mutex, so within the one process
//! that holds the root's lock (D1) a log has one writer at a time.
//!
//! Durability: `create` writes the header to a temporary file, syncs it
//! and publishes it with `hard_link`, which fails when the name exists, so
//! a log never appears half written and two creators cannot both win.
//! `append` writes one line ending in `\n` with one `write_all` on an
//! `O_APPEND` handle and syncs it before it returns `Ok`.
//!
//! The unacknowledged tail: `\n` is the last byte of every line and is
//! synced before `Ok`, so bytes after the last `\n` belong to an append
//! that never returned `Ok`. `load` ignores them and `append` truncates
//! them first. A tail longer than [`MAX_LINE_BYTES`] cannot be one, and
//! fails closed like a file without a complete header or any complete line
//! that does not decode; nothing then modifies the file. Error details
//! name the file and the line, never content (ADR-008, D9).

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::PoisonError;

use boneli_app::{RunLog, RunStart, StoreError};
use boneli_domain::{RunEvent, RunId};
use boneli_https::Sha256;

use crate::codec::{self, MAX_LINE_BYTES};
use crate::root::{RUNS, sync_dir};
use crate::{FsStore, Regular, hex, open_regular};

fn unavailable(detail: String) -> StoreError {
    StoreError::Unavailable { detail }
}

/// The log's name: the SHA-256 of the id's UTF-8 bytes, so every id maps
/// to one fixed-length lowercase ASCII name (D2).
fn log_name(id: &RunId) -> String {
    format!("{}.log", hex(&Sha256::digest(id.as_str().as_bytes())))
}

/// The log's path and its label for error details, relative to the root.
fn log_path(store: &FsStore, id: &RunId) -> (PathBuf, String) {
    let name = log_name(id);
    let label = format!("{RUNS}/{name}");
    (store.root.join(RUNS).join(name), label)
}

/// Opens the log at `path`: `UnknownRun` when there is none.
fn open_log(path: &Path, label: &str, options: &OpenOptions) -> Result<File, StoreError> {
    match open_regular(path, options) {
        Regular::File(file, _) => Ok(file),
        Regular::Missing => Err(StoreError::UnknownRun),
        Regular::Other => Err(unavailable(format!("{label}: not a regular file"))),
        Regular::Failed(e) => Err(unavailable(format!("{label}: {e}"))),
    }
}

/// A log as read: what it holds, and where its acknowledged lines end.
struct Parsed {
    log: RunLog,
    /// The length of the header and every complete line.
    complete: u64,
    /// The length of the file, the unacknowledged tail included.
    len: u64,
}

/// Reads and checks a whole log (D5). The header must name `id`.
fn read_log(file: &File, label: &str, id: &RunId) -> Result<Parsed, StoreError> {
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut complete: u64 = 0;
    let mut tail: u64 = 0;
    let mut number: u64 = 0;
    let mut start: Option<RunStart> = None;
    let mut events = Vec::new();
    // A line is read up to MAX_LINE_BYTES + 1 bytes: content and `\n` at
    // the limit, or proof that the line or tail is over it.
    let bound = u64::try_from(MAX_LINE_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    loop {
        line.clear();
        let got = (&mut reader)
            .take(bound)
            .read_until(b'\n', &mut line)
            .map_err(|e| unavailable(format!("{label}: {e}")))?;
        if got == 0 {
            break;
        }
        number += 1;
        let at =
            |what: &dyn std::fmt::Display| unavailable(format!("{label} line {number}: {what}"));
        let Some(content) = line.strip_suffix(b"\n") else {
            if line.len() > MAX_LINE_BYTES {
                return Err(at(&format_args!(
                    "longer than {MAX_LINE_BYTES} bytes without a line end"
                )));
            }
            // Short of the bound without `\n`: the end of the file.
            tail = len_u64(line.len());
            break;
        };
        match start {
            None => {
                let (owner, logged) = codec::read_header(content).map_err(|m| at(&m))?;
                if owner != *id {
                    return Err(at(&"the header names another run"));
                }
                start = Some(logged);
            }
            Some(_) => events.push(codec::read_event(content).map_err(|m| at(&m))?),
        }
        complete += len_u64(line.len());
    }
    let Some(start) = start else {
        return Err(unavailable(format!("{label}: no complete header line")));
    };
    Ok(Parsed {
        log: RunLog { start, events },
        complete,
        len: complete + tail,
    })
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

pub(crate) fn create(store: &FsStore, id: &RunId, start: &RunStart) -> Result<(), StoreError> {
    let _held = store
        .log_lock
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let (path, label) = log_path(store, id);
    let mut line = codec::header_line(id, start)
        .map_err(|e| unavailable(format!("{label}: cannot write the header: {e}")))?;
    line.push(b'\n');
    let runs = store.root.join(RUNS);
    let temp = store.temp_path(&runs);
    let result = publish(&temp, &path, &runs, &label, &line);
    // After the link the temporary name is a second name of the log;
    // after a failure it is a partial file. Either way it goes; a removal
    // that fails leaves a `.tmp-` name for the next `open` to sweep.
    let _ = fs::remove_file(&temp);
    result
}

/// Writes `bytes` to `temp`, syncs it and links it to `path`.
fn publish(
    temp: &Path,
    path: &Path,
    runs: &Path,
    label: &str,
    bytes: &[u8],
) -> Result<(), StoreError> {
    let io = |what: &str, e: io::Error| unavailable(format!("{label}: {what}: {e}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)
        .map_err(|e| io("create", e))?;
    file.write_all(bytes).map_err(|e| io("write", e))?;
    file.sync_data().map_err(|e| io("sync", e))?;
    match fs::hard_link(temp, path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(StoreError::AlreadyExists);
        }
        Err(e) => return Err(io("link", e)),
    }
    sync_dir(runs).map_err(|e| io("sync the directory", e))
}

pub(crate) fn append(store: &FsStore, id: &RunId, event: &RunEvent) -> Result<(), StoreError> {
    let _held = store
        .log_lock
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let (path, label) = log_path(store, id);
    let mut file = open_log(&path, &label, OpenOptions::new().read(true).append(true))?;
    let parsed = read_log(&file, &label, id)?;
    // Encoded and checked before the file is touched, so an event over a
    // limit leaves it byte for byte, tail included.
    let mut line = codec::event_line(event)
        .map_err(|e| unavailable(format!("{label}: cannot append: {e}")))?;
    line.push(b'\n');
    let io = |what: &str, e: io::Error| unavailable(format!("{label}: {what}: {e}"));
    if parsed.len > parsed.complete {
        file.set_len(parsed.complete)
            .map_err(|e| io("truncate the unacknowledged tail", e))?;
    }
    let written = file
        .write_all(&line)
        .map_err(|e| io("write", e))
        .and_then(|()| file.sync_data().map_err(|e| io("sync", e)));
    if written.is_err() {
        // Back to the acknowledged lines; if this fails too, what is left
        // after the last `\n` is a tail the next append truncates, and a
        // whole line is an event the run had accepted (D4).
        let _ = file.set_len(parsed.complete);
    }
    written
}

pub(crate) fn load(store: &FsStore, id: &RunId) -> Result<RunLog, StoreError> {
    let _held = store
        .log_lock
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let (path, label) = log_path(store, id);
    let file = open_log(&path, &label, OpenOptions::new().read(true))?;
    read_log(&file, &label, id).map(|parsed| parsed.log)
}
