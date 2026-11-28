//! [`MemorySandbox`]: the `Sandbox` port in memory.
//!
//! A pod is a workspace map, the files its programs wrote outside the
//! workspace (per container), and the layers it mounts. The workspace is
//! copied in from and exported to [`MemoryGit`](crate::MemoryGit)'s
//! snapshot format ([`pack_tree`]), which holds files only: an export of a
//! workspace with a symlink in it is `Failed`, never a tree with the link
//! dropped. The workspace sits at [`WORKSPACE`] in the first container;
//! a command in another container writes nothing into it.
//!
//! Writes replace and never follow: a write at a path removes what lay
//! beneath it and turns every file or symlink at a parent into a
//! directory, so the map stays a tree. `copy_out` refuses a symlink at the
//! path or at a parent (ADR-004, D11) and a path beneath a mounted
//! dependency, which is not part of the workspace (ADR-042, D5).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use boneli_app::{
    Command, ContainerName, ExecResult, ExitStatus, LayerRef, Limits, Phase, RelativePath, Sandbox,
    SandboxError, SandboxId, SandboxSpec, TreePath, overlapping_paths,
};

use crate::git::{Tree, pack_tree, unpack_tree};
use crate::lock;

/// Where the workspace is in the first container.
pub const WORKSPACE: &str = "/workspace";

/// What a [`Program`] writes at a workspace path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Write {
    /// A file with this content.
    File(Vec<u8>),
    /// A symlink with this target, kept as written.
    Symlink(Vec<u8>),
}

/// A scripted program of a [`MemorySandbox`]: what running it returns and
/// what it changes in the sandbox it runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// The name a [`Command`] calls it by.
    pub name: String,
    /// What a run returns.
    pub result: ExecResult,
    /// What a run writes into the workspace, in order; a later write to
    /// the same path replaces the earlier one. Only a run in the first
    /// container reaches the workspace, and a write beneath a mounted
    /// dependency is dropped, because the mount is read-only.
    pub writes: Vec<(RelativePath, Write)>,
    /// Files a run writes outside the workspace, in the container it runs
    /// in, by absolute path; applied before `writes`.
    pub outside: Vec<(String, Vec<u8>)>,
    /// Files a run copies, from an absolute path in the container it runs
    /// in (a mounted dependency under [`WORKSPACE`] included) to a
    /// workspace path; applied after `writes`. A source that is not a
    /// file copies nothing.
    pub copies: Vec<(String, RelativePath)>,
}

/// A live pod.
#[derive(Debug)]
struct Pod {
    spec: SandboxSpec,
    workspace: BTreeMap<TreePath, Write>,
    /// Files outside the workspace, by container and absolute path.
    outside: BTreeMap<(ContainerName, String), Vec<u8>>,
    /// The mounted dependency paths.
    mounts: Vec<TreePath>,
}

/// A sealed layer: its paths and what lay beneath them.
#[derive(Debug)]
struct Layer {
    paths: Vec<TreePath>,
    nodes: BTreeMap<TreePath, Write>,
}

#[derive(Debug, Default)]
struct State {
    /// The number of the next sandbox handle, starting at 1; never reused.
    next: u64,
    /// The number of the next layer handle, starting at 1; never reused.
    next_layer: u64,
    sandboxes: BTreeMap<SandboxId, Pod>,
    layers: BTreeMap<LayerRef, Layer>,
    commands: Vec<(SandboxId, Command)>,
}

/// A `Sandbox` that runs scripted [`Program`]s. Every sandbox has its own
/// workspace map; handles are `sandbox-<n>` and `layer-<n>` from counters
/// starting at 1, so a handle is never issued twice. A program the script
/// does not name exits with code 127 and the error output `program not
/// found`, as a shell does. It checks what needs no real process: the spec
/// through [`SandboxSpec::check`], the workspace format, the layers and
/// their paths, the workspace's inodes, the phase of a seal and the output
/// cap of an exec. The wall limit is not checked: nothing runs.
#[derive(Debug, Default)]
pub struct MemorySandbox {
    programs: BTreeMap<String, Program>,
    state: Mutex<State>,
}

fn failed(detail: String) -> SandboxError {
    SandboxError::Failed { detail }
}

/// Whether `inner` lies strictly beneath `outer`.
fn beneath(inner: &TreePath, outer: &TreePath) -> bool {
    inner
        .as_bytes()
        .strip_prefix(outer.as_bytes())
        .is_some_and(|rest| rest.first() == Some(&b'/'))
}

/// Every proper parent of `path`, the shortest first.
fn parents(path: &TreePath) -> Vec<TreePath> {
    let bytes = path.as_bytes();
    bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'/')
        .filter_map(|(k, _)| TreePath::parse(&bytes[..k]).ok())
        .collect()
}

/// Writes `node` at `path`, replacing what lay beneath it and every file
/// or symlink at a parent.
fn put(workspace: &mut BTreeMap<TreePath, Write>, path: TreePath, node: Write) {
    workspace.retain(|p, _| !beneath(p, &path));
    for parent in parents(&path) {
        workspace.remove(&parent);
    }
    workspace.insert(path, node);
}

/// Shows a path for a failure detail, escaped where it is not UTF-8.
fn show(path: &TreePath) -> String {
    path.as_bytes().escape_ascii().to_string()
}

impl Pod {
    /// The mount that `path` is or lies beneath.
    fn mount_of(&self, path: &TreePath) -> Option<&TreePath> {
        self.mounts.iter().find(|m| *m == path || beneath(path, m))
    }

    fn first(&self) -> &ContainerName {
        &self.spec.containers[0].name
    }

    fn has(&self, container: &ContainerName) -> bool {
        self.spec.containers.iter().any(|c| c.name == *container)
    }

    /// What sits at an absolute path of `container`, mounted layers
    /// included; no symlink is followed.
    fn lookup(
        &self,
        layers: &BTreeMap<LayerRef, Layer>,
        container: &ContainerName,
        path: &str,
    ) -> Option<Write> {
        let in_workspace = (container == self.first())
            .then(|| path.strip_prefix(WORKSPACE)?.strip_prefix('/'))
            .flatten();
        let Some(relative) = in_workspace else {
            return self
                .outside
                .get(&(container.clone(), String::from(path)))
                .cloned()
                .map(Write::File);
        };
        let tree_path = TreePath::parse(relative.as_bytes()).ok()?;
        if self.mount_of(&tree_path).is_some() {
            return self
                .spec
                .dependencies
                .iter()
                .filter_map(|l| layers.get(l))
                .find_map(|layer| layer.nodes.get(&tree_path).cloned());
        }
        self.workspace.get(&tree_path).cloned()
    }

    /// A workspace write of a run in `container`: dropped in any other
    /// container and beneath a read-only mount.
    fn write(&mut self, container: &ContainerName, path: TreePath, node: Write) {
        if container == self.first() && self.mount_of(&path).is_none() {
            put(&mut self.workspace, path, node);
        }
    }

    /// The first symlink or file at a parent of `path`.
    fn blocked_parent(&self, path: &TreePath) -> Option<(TreePath, &Write)> {
        parents(path)
            .into_iter()
            .find_map(|p| self.workspace.get(&p).map(|node| (p, node)))
    }
}

impl MemorySandbox {
    /// A sandbox that knows these programs; of two with the same name, the
    /// later one counts.
    pub fn new(programs: Vec<Program>) -> MemorySandbox {
        MemorySandbox {
            programs: programs.into_iter().map(|p| (p.name.clone(), p)).collect(),
            state: Mutex::new(State {
                next: 1,
                next_layer: 1,
                ..State::default()
            }),
        }
    }

    /// Every command run or started so far and the sandbox it ran in, in
    /// order.
    pub fn commands(&self) -> Vec<(SandboxId, Command)> {
        lock(&self.state).commands.clone()
    }

    /// What sits at an absolute path of a live sandbox's first container:
    /// a workspace or dependency entry under [`WORKSPACE`], a file a
    /// program wrote elsewhere; `None` for nothing. No symlink is
    /// followed. For tests that look at what a program left, as
    /// [`MemorySandbox::commands`] shows what ran.
    pub fn entry(&self, id: &SandboxId, path: &str) -> Option<Write> {
        let state = lock(&self.state);
        let pod = state.sandboxes.get(id)?;
        pod.lookup(&state.layers, pod.first(), path)
    }

    /// Runs a program's effects and returns its result, for `exec` and
    /// `start`; `None` for a program the script does not name.
    fn run(&self, state: &mut State, id: &SandboxId, command: &Command) -> Option<ExecResult> {
        let program = self.programs.get(&command.program)?;
        let State {
            sandboxes, layers, ..
        } = state;
        let pod = sandboxes.get_mut(id)?;
        let container = &command.container;
        for (path, content) in &program.outside {
            pod.outside
                .insert((container.clone(), path.clone()), content.clone());
        }
        for (path, node) in &program.writes {
            pod.write(container, TreePath::from(path), node.clone());
        }
        for (source, target) in &program.copies {
            if let Some(Write::File(content)) = pod.lookup(layers, container, source) {
                pod.write(container, TreePath::from(target), Write::File(content));
            }
        }
        Some(program.result.clone())
    }

    /// The live pod and the command's container, or why not.
    fn check_command(state: &State, id: &SandboxId, command: &Command) -> Result<(), SandboxError> {
        let pod = state
            .sandboxes
            .get(id)
            .ok_or(SandboxError::UnknownSandbox)?;
        if !pod.has(&command.container) {
            return Err(failed(format!(
                "the pod has no container named {:?}",
                command.container.as_str()
            )));
        }
        Ok(())
    }

    /// Everything `create` checks after the spec: the workspace, the
    /// layers and their paths, and the inodes. Returns the workspace and
    /// the mount paths.
    fn admit(
        state: &State,
        spec: &SandboxSpec,
    ) -> Result<(BTreeMap<TreePath, Write>, Vec<TreePath>), SandboxError> {
        let tree = unpack_tree(spec.workspace.as_bytes())
            .map_err(|e| failed(format!("the workspace: {e}")))?;
        let mut mounts = Vec::new();
        for layer in &spec.dependencies {
            let known = state.layers.get(layer).ok_or_else(|| {
                failed(format!(
                    "the layer {:?} is unknown or released",
                    layer.as_str()
                ))
            })?;
            mounts.extend(known.paths.iter().cloned());
        }
        for (k, a) in mounts.iter().enumerate() {
            if let Some(b) = mounts[k + 1..]
                .iter()
                .find(|b| a == *b || beneath(a, b) || beneath(b, a))
            {
                return Err(failed(format!(
                    "the dependency paths {} and {} overlap",
                    show(a),
                    show(b)
                )));
            }
        }
        for mount in &mounts {
            if let Some(file) = tree
                .keys()
                .find(|p| *p == mount || beneath(p, mount) || beneath(mount, p))
            {
                return Err(failed(format!(
                    "the dependency path {} overlaps the workspace file {}: the mount would \
                     hide it",
                    show(mount),
                    show(file)
                )));
            }
        }
        // Every file, every directory and every mount point, and the root.
        let mut nodes: BTreeSet<TreePath> = BTreeSet::new();
        for path in tree.keys().chain(&mounts) {
            nodes.insert(path.clone());
            nodes.extend(parents(path));
        }
        let inodes = u64::try_from(nodes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if inodes > spec.limits.workspace_inodes {
            return Err(failed(format!(
                "the workspace needs {inodes} inodes, workspace_inodes is {}",
                spec.limits.workspace_inodes
            )));
        }
        let workspace = tree
            .into_iter()
            .map(|(path, content)| (path, Write::File(content)))
            .collect();
        Ok((workspace, mounts))
    }
}

/// The stream of `result` that carries more than `cap` bytes.
fn over_cap(result: &ExecResult, cap: u64) -> Option<&'static str> {
    let over = |stream: &[u8]| u64::try_from(stream.len()).map_or(true, |n| n > cap);
    if over(&result.stdout) {
        Some("standard output")
    } else if over(&result.stderr) {
        Some("error output")
    } else {
        None
    }
}

impl Sandbox for MemorySandbox {
    fn create(&self, spec: &SandboxSpec) -> Result<SandboxId, SandboxError> {
        spec.check()
            .map_err(|problem| failed(format!("{problem}")))?;
        let mut state = lock(&self.state);
        let (workspace, mounts) = Self::admit(&state, spec)?;
        let n = state.next;
        state.next = n.saturating_add(1);
        let id = SandboxId::new(format!("sandbox-{n}"));
        state.sandboxes.insert(
            id.clone(),
            Pod {
                spec: spec.clone(),
                workspace,
                outside: BTreeMap::new(),
                mounts,
            },
        );
        Ok(id)
    }

    fn exec(
        &self,
        id: &SandboxId,
        command: &Command,
        limits: &Limits,
    ) -> Result<ExecResult, SandboxError> {
        let mut state = lock(&self.state);
        Self::check_command(&state, id, command)?;
        let result = self
            .run(&mut state, id, command)
            .unwrap_or_else(|| ExecResult {
                status: ExitStatus::Code(127),
                stdout: Vec::new(),
                stderr: b"program not found".to_vec(),
            });
        state.commands.push((id.clone(), command.clone()));
        match over_cap(&result, limits.output_bytes) {
            Some(stream) => Err(failed(format!(
                "the command's {stream} passed output_bytes {}; it was killed",
                limits.output_bytes
            ))),
            None => Ok(result),
        }
    }

    fn start(&self, id: &SandboxId, command: &Command) -> Result<(), SandboxError> {
        let mut state = lock(&self.state);
        Self::check_command(&state, id, command)?;
        let ran = self.run(&mut state, id, command);
        state.commands.push((id.clone(), command.clone()));
        match ran {
            Some(_) => Ok(()),
            None => Err(failed(format!(
                "the service {:?} exited at once: program not found",
                command.program
            ))),
        }
    }

    fn copy_out(&self, id: &SandboxId, path: &RelativePath) -> Result<Vec<u8>, SandboxError> {
        let state = lock(&self.state);
        let pod = state
            .sandboxes
            .get(id)
            .ok_or(SandboxError::UnknownSandbox)?;
        let path = TreePath::from(path);
        if let Some(mount) = pod.mount_of(&path) {
            return Err(failed(format!(
                "{} is beneath the dependency mount at {}, which is not part of the workspace",
                show(&path),
                show(mount)
            )));
        }
        match pod.blocked_parent(&path) {
            Some((parent, Write::Symlink(_))) => {
                return Err(failed(format!(
                    "the parent {} of {} is a symlink, which copy_out does not follow",
                    show(&parent),
                    show(&path)
                )));
            }
            Some((_, Write::File(_))) => return Err(SandboxError::NotFound),
            None => {}
        }
        match pod.workspace.get(&path) {
            Some(Write::File(content)) => Ok(content.clone()),
            Some(Write::Symlink(_)) => Err(failed(format!(
                "{} is a symlink, which copy_out does not follow",
                show(&path)
            ))),
            None => Err(SandboxError::NotFound),
        }
    }

    fn export(&self, id: &SandboxId) -> Result<Vec<u8>, SandboxError> {
        let state = lock(&self.state);
        let pod = state
            .sandboxes
            .get(id)
            .ok_or(SandboxError::UnknownSandbox)?;
        let mut tree = Tree::new();
        for (path, node) in &pod.workspace {
            match node {
                Write::File(content) => {
                    tree.insert(path.clone(), content.clone());
                }
                Write::Symlink(_) => {
                    return Err(failed(format!(
                        "{} is a symlink, which the in-memory snapshot format cannot carry",
                        show(path)
                    )));
                }
            }
        }
        Ok(pack_tree(&tree))
    }

    fn seal(&self, id: &SandboxId, paths: &[RelativePath]) -> Result<LayerRef, SandboxError> {
        let mut state = lock(&self.state);
        let pod = state
            .sandboxes
            .get(id)
            .ok_or(SandboxError::UnknownSandbox)?;
        if pod.spec.phase != Phase::Prepare {
            return Err(failed(format!(
                "only a Prepare sandbox can be sealed, this one is {:?}",
                pod.spec.phase
            )));
        }
        if paths.is_empty() {
            return Err(failed(String::from("a seal needs at least one path")));
        }
        if let Some((a, b)) = overlapping_paths(paths) {
            return Err(failed(format!(
                "the paths {:?} and {:?} overlap",
                a.as_str(),
                b.as_str()
            )));
        }
        let mut layer = Layer {
            paths: Vec::new(),
            nodes: BTreeMap::new(),
        };
        for path in paths {
            let path = TreePath::from(path);
            if pod.blocked_parent(&path).is_some() || pod.workspace.contains_key(&path) {
                return Err(failed(format!(
                    "{} or one of its parents is not a directory",
                    show(&path)
                )));
            }
            let before = layer.nodes.len();
            layer.nodes.extend(
                pod.workspace
                    .iter()
                    .filter(|(p, _)| beneath(p, &path))
                    .map(|(p, node)| (p.clone(), node.clone())),
            );
            if layer.nodes.len() == before {
                return Err(failed(format!(
                    "the workspace has no directory {}",
                    show(&path)
                )));
            }
            layer.paths.push(path);
        }
        let n = state.next_layer;
        state.next_layer = n.saturating_add(1);
        let reference = LayerRef::new(format!("layer-{n}"));
        state.layers.insert(reference.clone(), layer);
        Ok(reference)
    }

    fn release(&self, layer: &LayerRef) -> Result<(), SandboxError> {
        let mut state = lock(&self.state);
        if !state.layers.contains_key(layer) {
            return Err(failed(format!(
                "the layer {:?} is unknown or released",
                layer.as_str()
            )));
        }
        if let Some((id, _)) = state
            .sandboxes
            .iter()
            .find(|(_, pod)| pod.spec.dependencies.contains(layer))
        {
            return Err(failed(format!(
                "the layer {:?} is mounted by {:?}",
                layer.as_str(),
                id.as_str()
            )));
        }
        state.layers.remove(layer);
        Ok(())
    }

    fn destroy(&self, id: &SandboxId) -> Result<(), SandboxError> {
        match lock(&self.state).sandboxes.remove(id) {
            Some(_) => Ok(()),
            None => Err(SandboxError::UnknownSandbox),
        }
    }
}
