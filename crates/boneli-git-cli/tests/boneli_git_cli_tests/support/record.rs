//! A recording git: a shell script the adapter runs as its git binary. It
//! records each call's argv, environment and working directory, exactly as
//! the kernel handed them to the process (`/proc/self/{cmdline,environ,cwd}`
//! of the script's shell), then `exec`s the real git with the same
//! arguments.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{TempDir, host_git};

/// One recorded call.
#[derive(Clone, Debug)]
pub struct Call {
    /// The arguments after the program name.
    pub args: Vec<String>,
    /// `KEY=value`, in the order the process got them.
    pub env: Vec<(String, String)>,
    /// The working directory.
    pub cwd: PathBuf,
}

impl Call {
    /// The environment's keys, sorted.
    pub fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.env.iter().map(|(k, _)| k.clone()).collect();
        keys.sort();
        keys
    }

    /// The value of `key`.
    pub fn var(&self, key: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The git subcommand: the first argument that is not a global option.
    pub fn subcommand(&self) -> Option<&str> {
        self.args
            .iter()
            .find(|a| !a.starts_with('-'))
            .map(String::as_str)
    }
}

/// The script and its log directory.
pub struct Recorder {
    pub git: PathBuf,
    pub log: PathBuf,
}

impl Recorder {
    /// Writes `<tmp>/record/git` around `real` (the test's own git when
    /// `None`) and an empty `<tmp>/record/log`.
    pub fn new(tmp: &TempDir) -> Recorder {
        Recorder::wrapping(tmp, &host_git())
    }

    pub fn wrapping(tmp: &TempDir, real: &Path) -> Recorder {
        let dir = tmp.path().join("record");
        let log = dir.join("log");
        fs::create_dir_all(&log).expect("record dir");
        let git = dir.join("git");
        let script = format!(
            "#!/bin/sh\n\
             d=$(mktemp -d '{log}/call.XXXXXXXX') || exit 97\n\
             cat /proc/$$/cmdline > \"$d/cmdline\"\n\
             cat /proc/$$/environ > \"$d/environ\"\n\
             readlink /proc/$$/cwd > \"$d/cwd\"\n\
             exec '{real}' \"$@\"\n",
            log = log.display(),
            real = real.display(),
        );
        fs::write(&git, script).expect("write the recorder");
        fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).expect("mode");
        Recorder { git, log }
    }

    /// Every call so far, in no particular order.
    pub fn calls(&self) -> Vec<Call> {
        let mut calls = Vec::new();
        for entry in fs::read_dir(&self.log).expect("the log") {
            let dir = entry.expect("entry").path();
            let cmdline = fs::read(dir.join("cmdline")).expect("cmdline");
            // The shell's argv: the interpreter, the script, then git's.
            let cmdline = cmdline.strip_suffix(&[0]).unwrap_or(&cmdline);
            let args: Vec<String> = cmdline
                .split(|b| *b == 0)
                .skip(2)
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            let environ = fs::read(dir.join("environ")).expect("environ");
            let env = environ
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let s = String::from_utf8_lossy(s).into_owned();
                    let (k, v) = s.split_once('=').expect("KEY=value");
                    (k.to_owned(), v.to_owned())
                })
                .collect();
            let cwd = fs::read_to_string(dir.join("cwd")).expect("cwd");
            calls.push(Call {
                args,
                env,
                cwd: PathBuf::from(cwd.trim_end()),
            });
        }
        calls
    }

    /// Forgets every call so far.
    pub fn clear(&self) {
        for entry in fs::read_dir(&self.log).expect("the log") {
            fs::remove_dir_all(entry.expect("entry").path()).expect("clear");
        }
    }
}

/// A fake git that answers `version` with a supported version and fails
/// every other call with `status` and no output.
pub fn silent_failure(tmp: &TempDir, status: u8) -> PathBuf {
    let git = tmp.path().join("silent-git");
    fs::write(
        &git,
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = version ]; then echo 'git version 2.56.0'; exit 0; fi\n\
             exit {status}\n"
        ),
    )
    .expect("write the fake git");
    fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).expect("mode");
    git
}

/// A fake git that answers `version` with `answer` and nothing else.
pub fn version_only(tmp: &TempDir, name: &str, answer: &str) -> PathBuf {
    let git = tmp.path().join(name);
    fs::write(&git, format!("#!/bin/sh\nprintf '%s\\n' '{answer}'\n")).expect("write the fake git");
    fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).expect("mode");
    git
}
