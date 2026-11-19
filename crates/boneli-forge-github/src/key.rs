//! The App's private key file (ADR-014, D6).
//!
//! The key comes from a file, never from an environment variable, which
//! every child process would inherit. The file must be an absolute path to
//! a regular file, not a symlink, owned by the process's uid and with no
//! permission bit for group or others: the ssh client's rule for private
//! keys, because disclosure is the threat. Replacement is not (a swapped
//! key only signs JWTs GitHub refuses), so no ancestor directory is
//! checked. The file is read once, by [`load_key`].

use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use boneli_https::{KeyError, RsaSha256Key};

/// What [`key_file_problem`] reads from a file's metadata. Public so the
/// rule can be tested with facts no test user can produce (another owner).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyFileFacts {
    /// `lstat` saw a symlink.
    pub symlink: bool,
    /// A regular file (not a directory, FIFO, socket or device).
    pub regular: bool,
    /// The owner's uid.
    pub uid: u32,
    /// `st_mode`, type bits included.
    pub mode: u32,
}

impl KeyFileFacts {
    fn of(meta: &Metadata) -> KeyFileFacts {
        let kind = meta.file_type();
        KeyFileFacts {
            symlink: kind.is_symlink(),
            regular: kind.is_file()
                && !kind.is_fifo()
                && !kind.is_socket()
                && !kind.is_block_device()
                && !kind.is_char_device(),
            uid: meta.uid(),
            mode: meta.mode(),
        }
    }
}

/// A broken rule of the key file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyFileProblem {
    /// The path is a symlink.
    Symlink,
    /// Not a regular file.
    NotRegular,
    /// Another user owns it.
    Owner {
        /// The file's owner.
        owner: u32,
        /// This process's uid.
        process: u32,
    },
    /// Group or others have a permission bit (`mode & 0o077`).
    Mode(u32),
}

/// The first rule `facts` break for a process running as `process_uid`.
pub fn key_file_problem(facts: &KeyFileFacts, process_uid: u32) -> Option<KeyFileProblem> {
    if facts.symlink {
        Some(KeyFileProblem::Symlink)
    } else if !facts.regular {
        Some(KeyFileProblem::NotRegular)
    } else if facts.uid != process_uid {
        Some(KeyFileProblem::Owner {
            owner: facts.uid,
            process: process_uid,
        })
    } else if facts.mode & 0o077 != 0 {
        Some(KeyFileProblem::Mode(facts.mode & 0o7777))
    } else {
        None
    }
}

/// Why [`load_key`] refused. No variant carries key bytes or a parser's
/// quote of them.
#[derive(Debug)]
pub enum KeyFileError {
    /// The path is relative (`~` is not expanded).
    NotAbsolute,
    /// The file could not be inspected, opened or read.
    Io(io::ErrorKind),
    /// The process's uid could not be read from `/proc/self`.
    OwnUid(io::ErrorKind),
    /// A rule of the file is broken.
    Problem(KeyFileProblem),
    /// The file opened is not the file inspected: it was replaced between
    /// the two.
    Replaced,
    /// The file is longer than [`RsaSha256Key::MAX_PEM_LEN`].
    TooLarge,
    /// The content is not a key `RsaSha256Key` accepts.
    Key(KeyError),
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFileError::NotAbsolute => f.write_str("the key file path must be absolute"),
            KeyFileError::Io(kind) => write!(f, "the key file cannot be read: {kind}"),
            KeyFileError::OwnUid(kind) => write!(f, "cannot read the process's uid: {kind}"),
            KeyFileError::Problem(KeyFileProblem::Symlink) => {
                f.write_str("the key file is a symlink")
            }
            KeyFileError::Problem(KeyFileProblem::NotRegular) => {
                f.write_str("the key file is not a regular file")
            }
            KeyFileError::Problem(KeyFileProblem::Owner { owner, process }) => write!(
                f,
                "the key file is owned by uid {owner}, not by this process's uid {process}"
            ),
            KeyFileError::Problem(KeyFileProblem::Mode(mode)) => write!(
                f,
                "the key file has mode {mode:04o}; group and others must have no access (0600 or 0400)"
            ),
            KeyFileError::Replaced => {
                f.write_str("the key file was replaced while it was being opened")
            }
            KeyFileError::TooLarge => f.write_str("the key file is larger than 16384 bytes"),
            KeyFileError::Key(e) => write!(f, "the key file holds no usable key: {e}"),
        }
    }
}

impl std::error::Error for KeyFileError {}

/// The uid this process runs as: the owner of `/proc/self`.
fn own_uid() -> Result<u32, KeyFileError> {
    fs::metadata("/proc/self")
        .map(|m| m.uid())
        .map_err(|e| KeyFileError::OwnUid(e.kind()))
}

/// Reads the App key from `path` under the rules of this module: `lstat`
/// first, then the file is opened and its `fstat` must name the same
/// device and inode and pass the rules again, then at most
/// [`RsaSha256Key::MAX_PEM_LEN`] bytes are read and parsed. The buffer is
/// wiped on every path ([`RsaSha256Key::from_pem`] wipes what it is
/// given).
pub fn load_key(path: &Path) -> Result<RsaSha256Key, KeyFileError> {
    if !path.is_absolute() {
        return Err(KeyFileError::NotAbsolute);
    }
    let uid = own_uid()?;
    let before = fs::symlink_metadata(path).map_err(|e| KeyFileError::Io(e.kind()))?;
    if let Some(problem) = key_file_problem(&KeyFileFacts::of(&before), uid) {
        return Err(KeyFileError::Problem(problem));
    }
    let file = File::open(path).map_err(|e| KeyFileError::Io(e.kind()))?;
    let opened = file.metadata().map_err(|e| KeyFileError::Io(e.kind()))?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err(KeyFileError::Replaced);
    }
    if let Some(problem) = key_file_problem(&KeyFileFacts::of(&opened), uid) {
        return Err(KeyFileError::Problem(problem));
    }
    let cap = RsaSha256Key::MAX_PEM_LEN as u64;
    let mut pem = Vec::with_capacity(RsaSha256Key::MAX_PEM_LEN + 1);
    let read = file.take(cap + 1).read_to_end(&mut pem);
    if let Err(e) = read {
        pem.fill(0);
        return Err(KeyFileError::Io(e.kind()));
    }
    if pem.len() as u64 > cap {
        pem.fill(0);
        return Err(KeyFileError::TooLarge);
    }
    RsaSha256Key::from_pem(&mut pem).map_err(KeyFileError::Key)
}
