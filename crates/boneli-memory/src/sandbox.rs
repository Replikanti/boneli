//! [`MemorySandbox`]: the `Sandbox` port in memory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use boneli_app::{
    Command, ExecResult, ExitStatus, Limits, RelativePath, Sandbox, SandboxError, SandboxId,
    SandboxSpec,
};

use crate::lock;

/// A scripted program of a [`MemorySandbox`]: what running it returns and
/// the files it writes into the workspace of the sandbox it runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// The name a [`Command`] calls it by.
    pub name: String,
    /// What a run returns.
    pub result: ExecResult,
    /// The files a run writes, in order; a later write to the same path
    /// replaces the earlier content.
    pub writes: Vec<(RelativePath, Vec<u8>)>,
}

#[derive(Debug, Default)]
struct State {
    /// The number of the next handle, starting at 1; never reused.
    next: u64,
    /// The workspace of every live sandbox.
    sandboxes: BTreeMap<SandboxId, BTreeMap<RelativePath, Vec<u8>>>,
    commands: Vec<(SandboxId, Command)>,
}

/// A `Sandbox` that runs scripted [`Program`]s. Every sandbox has its own
/// workspace map; handles are `sandbox-<n>` from a counter starting at 1,
/// so a handle is never issued twice. A program the script does not name
/// exits with code 127 and the error output `program not found`, as a
/// shell does. The spec and the limits are not checked: nothing runs.
#[derive(Debug, Default)]
pub struct MemorySandbox {
    programs: BTreeMap<String, Program>,
    state: Mutex<State>,
}

impl MemorySandbox {
    /// A sandbox that knows these programs; of two with the same name, the
    /// later one counts.
    pub fn new(programs: Vec<Program>) -> MemorySandbox {
        MemorySandbox {
            programs: programs.into_iter().map(|p| (p.name.clone(), p)).collect(),
            state: Mutex::new(State {
                next: 1,
                ..State::default()
            }),
        }
    }

    /// Every command run so far and the sandbox it ran in, in order.
    pub fn commands(&self) -> Vec<(SandboxId, Command)> {
        lock(&self.state).commands.clone()
    }
}

impl Sandbox for MemorySandbox {
    fn create(&self, _spec: &SandboxSpec) -> Result<SandboxId, SandboxError> {
        let mut state = lock(&self.state);
        let n = state.next;
        state.next = n.saturating_add(1);
        let id = SandboxId::new(format!("sandbox-{n}"));
        state.sandboxes.insert(id.clone(), BTreeMap::new());
        Ok(id)
    }

    fn exec(
        &self,
        id: &SandboxId,
        command: &Command,
        _limits: &Limits,
    ) -> Result<ExecResult, SandboxError> {
        let mut state = lock(&self.state);
        let workspace = state
            .sandboxes
            .get_mut(id)
            .ok_or(SandboxError::UnknownSandbox)?;
        let result = match self.programs.get(&command.program) {
            Some(program) => {
                for (path, content) in &program.writes {
                    workspace.insert(path.clone(), content.clone());
                }
                program.result.clone()
            }
            None => ExecResult {
                status: ExitStatus::Code(127),
                stdout: Vec::new(),
                stderr: b"program not found".to_vec(),
            },
        };
        state.commands.push((id.clone(), command.clone()));
        Ok(result)
    }

    fn copy_out(&self, id: &SandboxId, path: &RelativePath) -> Result<Vec<u8>, SandboxError> {
        let state = lock(&self.state);
        let workspace = state
            .sandboxes
            .get(id)
            .ok_or(SandboxError::UnknownSandbox)?;
        workspace.get(path).cloned().ok_or(SandboxError::NotFound)
    }

    fn destroy(&self, id: &SandboxId) -> Result<(), SandboxError> {
        match lock(&self.state).sandboxes.remove(id) {
            Some(_) => Ok(()),
            None => Err(SandboxError::UnknownSandbox),
        }
    }
}
