//! The git runner (ADR-010, D4): every git process the adapter starts.
//!
//! - The binary is an absolute path; `PATH` is never searched.
//! - The environment is cleared and then holds exactly [`Runner`]'s fixed
//!   variables, a throwaway `GIT_INDEX_FILE` where a call needs one, a
//!   throwaway `GIT_OBJECT_DIRECTORY` with the store's objects as its only
//!   alternate where a call must not write into the store, and the
//!   command-scope config of [`CONFIG`] through `GIT_CONFIG_COUNT`,
//!   `GIT_CONFIG_KEY_n` and `GIT_CONFIG_VALUE_n`. Nothing from the host's
//!   environment reaches git (`GIT_DIR`, `GIT_CONFIG_PARAMETERS`, `HOME`,
//!   `GIT_SSH_COMMAND`, ...), no system or global config is read, and the
//!   command scope overrides any repository config.
//! - Every call but `version` names its repository with `--git-dir` and
//!   runs with that directory as its working directory, so git never
//!   discovers a repository; only the calls that read a workspace add
//!   `--work-tree`.
//! - stdin is written from its own thread, so a large input cannot
//!   deadlock against a full stdout pipe.
//! - A failure's detail is git's stderr, or the exit status or signal when
//!   stderr is blank (ADR-004, D4). git's messages are reported, never
//!   parsed. A failure also says whether git answered: it ran and exited
//!   with a non-zero status, or it gave no answer at all (it could not
//!   start, be waited for or read, or a signal ended it).
//! - Only a network call (`fetch`, `ls-remote`, `push`) carries an
//!   `Authorization` value, as one more command-scope pair
//!   `http.<url>.extraHeader`, and the detail of its failure has the value
//!   redacted (ADR-014, D3). Only `commit-tree` carries an identity, as
//!   `GIT_AUTHOR_*` and `GIT_COMMITTER_*`.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use boneli_app::CommitInfo;

use crate::credentials::redact;
use crate::url::Transports;

/// The oldest git the adapter runs: 2.39.1, the first release of the 2.39
/// line with the fix for CVE-2022-23521, an integer overflow in
/// `.gitattributes` parsing, and `diff` parses agent-written
/// `.gitattributes` (ADR-010, D7). Older maintenance releases with the fix
/// (2.30.7 to 2.38.3) are refused too; a version string cannot tell a
/// patched build from an unpatched one, so the floor fails closed.
pub const MIN_GIT_VERSION: (u64, u64, u64) = (2, 39, 1);

/// The command-scope config of every call (ADR-010, D4), in order. The
/// file protocol is added after `protocol.https.allow` for
/// [`Transports::HttpsAndFile`] only.
const CONFIG: &[(&str, &str)] = &[
    // Nothing a repository or workspace names runs.
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("core.untrackedCache", "false"),
    // Bytes are stored as written, modes and links as they are.
    ("core.autocrlf", "false"),
    ("core.symlinks", "true"),
    ("core.fileMode", "true"),
    ("core.ignoreCase", "false"),
    // Names that are `.git` elsewhere (`.GIT`, `git~1`, `.git.`) fail.
    ("core.protectNTFS", "true"),
    ("core.protectHFS", "true"),
    // No credential helper runs; the token path is #19's.
    ("credential.helper", ""),
    ("safe.bareRepository", "explicit"),
    ("protocol.allow", "never"),
    ("protocol.https.allow", "always"),
    ("protocol.version", "2"),
    ("transfer.fsckObjects", "true"),
    ("fetch.recurseSubmodules", "false"),
    ("submodule.recurse", "false"),
    // A push sends the one ref it names: no submodules, no tags, no
    // signed-push negotiation (ADR-014, D3).
    ("push.recurseSubmodules", "no"),
    ("push.followTags", "false"),
    ("push.gpgSign", "false"),
    ("http.followRedirects", "false"),
    // Under 1 byte per second for 5 minutes is a stalled transfer.
    ("http.lowSpeedLimit", "1"),
    ("http.lowSpeedTime", "300"),
    // No background work, and packs that are the same bytes every time.
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("pack.threads", "1"),
    ("pack.writeReverseIndex", "false"),
];

/// Where a call runs.
pub(crate) struct Call<'a> {
    /// `--git-dir`, also the working directory; `None` only for `version`.
    pub git_dir: Option<&'a Path>,
    /// `--work-tree`.
    pub work_tree: Option<&'a Path>,
    /// `GIT_INDEX_FILE`.
    pub index: Option<&'a Path>,
    /// `GIT_OBJECT_DIRECTORY`, a throwaway directory that new objects go
    /// to; `<git_dir>/objects` is then its only alternate, read and never
    /// written.
    pub objects: Option<&'a Path>,
    /// Bytes for stdin; stdin is empty without them.
    pub stdin: Option<&'a [u8]>,
    /// The author and committer of `commit-tree`.
    pub identity: Option<&'a CommitInfo>,
    /// The `Authorization` value of a network call and the URL it is
    /// scoped to; checked before the call is made.
    pub authorization: Option<Authorization<'a>>,
}

/// An `Authorization` header value scoped to one repository URL.
#[derive(Clone, Copy)]
pub(crate) struct Authorization<'a> {
    /// The repository URL, exactly as passed to git.
    pub url: &'a str,
    /// The header value, for example `Basic <base64>`.
    pub value: &'a str,
}

impl Call<'_> {
    /// A call on `git_dir` with nothing else.
    pub(crate) fn on(git_dir: &Path) -> Call<'_> {
        Call {
            git_dir: Some(git_dir),
            work_tree: None,
            index: None,
            objects: None,
            stdin: None,
            identity: None,
            authorization: None,
        }
    }
}

/// `path` as one entry of `GIT_ALTERNATE_OBJECT_DIRECTORIES`: in double
/// quotes, every byte but `[A-Za-z0-9/._-]` as a three-digit octal escape.
/// git C-unquotes an entry that starts with `"`, so neither the separator
/// `:` nor a leading `"` or `#` in the root's path changes what it names.
fn alternate(path: &Path) -> OsString {
    let mut out = vec![b'"'];
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-') {
            out.push(b);
        } else {
            out.extend_from_slice(format!("\\{b:03o}").as_bytes());
        }
    }
    out.push(b'"');
    OsString::from_vec(out)
}

/// Why a call failed.
#[derive(Debug)]
pub(crate) struct RunError {
    /// git's stderr, or the status, signal or error when that is blank.
    pub detail: String,
    /// git ran and exited with a non-zero status, its output read in full:
    /// an answer from git. `false` when git could not start, be waited for
    /// or read, or a signal ended it.
    pub answered: bool,
}

impl RunError {
    fn no_answer(detail: String) -> RunError {
        RunError {
            detail,
            answered: false,
        }
    }
}

/// Starts git processes under the rules above.
#[derive(Debug)]
pub(crate) struct Runner {
    git: PathBuf,
    home: PathBuf,
    transports: Transports,
}

impl Runner {
    /// `git` must be absolute; `home` is the empty private `HOME`.
    pub(crate) fn new(git: PathBuf, home: PathBuf, transports: Transports) -> Runner {
        Runner {
            git,
            home,
            transports,
        }
    }

    fn config(&self) -> Vec<(&'static str, &'static str)> {
        let mut config = Vec::with_capacity(CONFIG.len() + 1);
        for &(key, value) in CONFIG {
            config.push((key, value));
            if key == "protocol.https.allow" && self.transports == Transports::HttpsAndFile {
                config.push(("protocol.file.allow", "always"));
            }
        }
        config
    }

    /// Runs `git <global options> <args>` and returns stdout, or why it
    /// failed. The detail of a call that carried an `Authorization` value
    /// has that value, and its part after the scheme, redacted.
    pub(crate) fn run(&self, call: Call<'_>, args: &[&OsStr]) -> Result<Vec<u8>, RunError> {
        let value = call.authorization.map(|a| a.value);
        self.start(call, args).map_err(|mut e| {
            if let Some(value) = value {
                e.detail = redact(&e.detail, value);
            }
            e
        })
    }

    fn start(&self, call: Call<'_>, args: &[&OsStr]) -> Result<Vec<u8>, RunError> {
        let mut command = Command::new(&self.git);
        command.env_clear();
        let home = self.home.as_os_str();
        command
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_LITERAL_PATHSPECS", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_ALLOW_PROTOCOL", self.transports.allow_protocol())
            .env("GIT_PROTOCOL_FROM_USER", "0")
            .env("LC_ALL", "C")
            .env("TZ", "UTC");
        let config = self.config();
        let extra = usize::from(call.authorization.is_some());
        command.env("GIT_CONFIG_COUNT", (config.len() + extra).to_string());
        for (n, (key, value)) in config.iter().enumerate() {
            command
                .env(format!("GIT_CONFIG_KEY_{n}"), key)
                .env(format!("GIT_CONFIG_VALUE_{n}"), value);
        }
        if let Some(auth) = call.authorization {
            let n = config.len();
            command
                .env(
                    format!("GIT_CONFIG_KEY_{n}"),
                    format!("http.{}.extraHeader", auth.url),
                )
                .env(
                    format!("GIT_CONFIG_VALUE_{n}"),
                    format!("Authorization: {}", auth.value),
                );
        }
        if let Some(identity) = call.identity {
            command
                .env("GIT_AUTHOR_NAME", identity.name())
                .env("GIT_AUTHOR_EMAIL", identity.email())
                .env("GIT_COMMITTER_NAME", identity.name())
                .env("GIT_COMMITTER_EMAIL", identity.email());
        }
        if let Some(index) = call.index {
            command.env("GIT_INDEX_FILE", index);
        }
        if let Some(objects) = call.objects {
            let store = call.git_dir.ok_or_else(|| {
                RunError::no_answer("a throwaway object directory needs a --git-dir".to_owned())
            })?;
            command.env("GIT_OBJECT_DIRECTORY", objects).env(
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                alternate(&store.join("objects")),
            );
        }
        match call.git_dir {
            Some(dir) => {
                let mut flag = std::ffi::OsString::from("--git-dir=");
                flag.push(dir);
                command.arg(flag).current_dir(dir);
            }
            None => {
                command.current_dir(&self.home);
            }
        }
        if let Some(tree) = call.work_tree {
            let mut flag = std::ffi::OsString::from("--work-tree=");
            flag.push(tree);
            command.arg(flag);
        }
        command.args(args);
        let name = args
            .first()
            .map(|a| a.to_string_lossy().into_owned())
            .unwrap_or_default();
        command
            .stdin(if call.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| RunError::no_answer(format!("git {name}: cannot start git: {e}")))?;
        let writer = match (call.stdin, child.stdin.take()) {
            (Some(bytes), Some(mut pipe)) => {
                let bytes = bytes.to_vec();
                // A write error (git exited early) shows in its status.
                Some(std::thread::spawn(move || {
                    let _ = pipe.write_all(&bytes);
                }))
            }
            _ => None,
        };
        let mut stderr_pipe = child.stderr.take();
        let stderr_reader = std::thread::spawn(move || {
            let mut err = Vec::new();
            if let Some(pipe) = stderr_pipe.as_mut() {
                let _ = pipe.read_to_end(&mut err);
            }
            err
        });
        let mut stdout = Vec::new();
        let read = child
            .stdout
            .take()
            .map(|mut pipe| pipe.read_to_end(&mut stdout));
        let status = child
            .wait()
            .map_err(|e| RunError::no_answer(format!("git {name}: cannot wait for git: {e}")))?;
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        let stderr = stderr_reader.join().unwrap_or_default();
        if let Some(Err(e)) = read {
            return Err(RunError::no_answer(format!(
                "git {name}: cannot read its output: {e}"
            )));
        }
        if status.success() {
            return Ok(stdout);
        }
        let text = String::from_utf8_lossy(&stderr);
        let text = text.trim();
        let detail = if !text.is_empty() {
            format!("git {name}: {text}")
        } else if let Some(code) = status.code() {
            format!("git {name}: exit status {code}, no error output")
        } else if let Some(signal) = status.signal() {
            format!("git {name}: killed by signal {signal}, no error output")
        } else {
            format!("git {name}: failed, no error output and no status")
        };
        Err(RunError {
            detail,
            answered: status.code().is_some(),
        })
    }
}

/// The version `git version` prints, as `(major, minor, patch)`: the third
/// word's first three dot-separated components, each all digits. Anything
/// else is `None`.
pub(crate) fn parse_version(output: &str) -> Option<(u64, u64, u64)> {
    let mut words = output.split_whitespace();
    if words.next()? != "git" || words.next()? != "version" {
        return None;
    }
    let mut parts = words.next()?.split('.');
    let mut number = || -> Option<u64> {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    Some((number()?, number()?, number()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_floor() {
        let accepted = [
            "git version 2.39.1",
            "git version 2.40.0",
            "git version 2.100.0",
            "git version 3.0.0",
            "git version 2.43.0.windows.1",
            "git version 2.39.5 (Apple Git-154)\n",
        ];
        for text in accepted {
            let v = parse_version(text).unwrap_or_else(|| panic!("{text:?}"));
            assert!(v >= MIN_GIT_VERSION, "{text:?}");
        }
        let refused = [
            "git version 2.39.0",
            "git version 2.38.3",
            "git version 1.99.99",
        ];
        for text in refused {
            let v = parse_version(text).unwrap_or_else(|| panic!("{text:?}"));
            assert!(v < MIN_GIT_VERSION, "{text:?}");
        }
        for text in [
            "",
            "git version x",
            "git version 2.39",
            "git version 2..1",
            "git version +2.39.1",
            "version 2.39.1",
            "git 2.39.1",
            "git version 2.39.1x",
        ] {
            assert_eq!(parse_version(text), None, "{text:?}");
        }
        // Numeric, not lexical: 2.100 is newer than 2.39.
        assert!(parse_version("git version 2.100.0") > parse_version("git version 2.39.1"));
    }

    #[test]
    fn alternate_is_quoted() {
        let quoted = |p: &[u8]| alternate(Path::new(OsStr::from_bytes(p))).into_vec();
        assert_eq!(quoted(b"/r/s_1/a-b.c"), b"\"/r/s_1/a-b.c\"");
        assert_eq!(
            quoted(b"/a:b\"#c \\\xff"),
            b"\"/a\\072b\\042\\043c\\040\\134\\377\""
        );
    }

    #[test]
    fn file_protocol_only_with_the_file_transport() {
        let runner = |t| Runner::new(PathBuf::from("/g"), PathBuf::from("/h"), t);
        let https = runner(Transports::Https).config();
        let file = runner(Transports::HttpsAndFile).config();
        assert_eq!(https.len(), CONFIG.len());
        assert!(!https.iter().any(|(k, _)| k.starts_with("protocol.file")));
        assert_eq!(file.len(), CONFIG.len() + 1);
        assert!(file.contains(&("protocol.file.allow", "always")));
    }
}
