# ADR-042: The Linux sandbox adapter: pods, workspace exchange and fail-closed outcomes

- Status: proposed
- Date: 2026-11-28

## Context

#8 builds `boneli-sandbox-linux`, the real adapter of the `Sandbox` port
on the runtime of ADR-007. It lands in six pull requests, and this ADR
grows with them: each PR adds the decision it implements, and the last
one accepts the ADR. This revision holds D1, from part 1, and D2, from
part 2.

The sandbox copies a workspace in when a sandbox is created and exports
one when the agent is done (ADR-004, D11). The format is ADR-010's (D2):
a magic line and canonical, length-prefixed entries, which the git
adapter decodes on the host before it writes them with `materialize`
(D3) and runs git over them. Both live in `boneli-git-cli`, and an
adapter cannot depend on another adapter (rule `graph-adapter`,
ADR-001). ADR-010 named the way out in its consequences: when #8 needs
the codec, it moves `Workspace` and `materialize` into a support crate
and passes the path rule in, so the support crate stays generic. Since
ADR-018 that rule is the tree path rule (`TreePath::parse` and
`TreePath::is_repository_metadata`), not the citation rule ADR-010 named.

Support crates depend on support crates only (rule `graph-support`), so
the moved code cannot name `TreePath`, which lives in the core crate
`boneli-app`.

One rule differs between the two users. The git adapter refuses
repository metadata in `materialize` as defense in depth: its `diff`
drops metadata first, so an entry there is a bug upstream. The
sandbox's snapshot carries its generated one-commit `.git` on purpose
(ADR-010, D1), and the copy-in must write it.

## Decision

### D1. The workspace format in a support crate, `boneli-workspace`

`Workspace`, `DecodeError`, `EntryProblem`, `Kind`, `MAGIC`,
`DEFAULT_MAX_NODES` and `materialize` (with `MaterializeError`,
`DirectoryProblem` and `Item`) move from `boneli-git-cli` to a new
std-only support crate, `boneli-workspace`, listed in `roles.support` of
`tools/architecture.toml`. It has no dependencies. The code moves with
its unit tests, and nothing it checks or refuses changes.

**The path rule is a type parameter.** The crate defines

```rust
pub trait PathRule {
    type Path: Clone + Debug;
    type Problem: Debug;
    fn check(path: &[u8]) -> Result<Self::Path, Self::Problem>;
    fn is_metadata(path: &[u8]) -> bool;
    fn bytes(path: &Self::Path) -> &[u8];
}
```

and `Workspace<R: PathRule>` keeps each entry under the rule's own path
type, so `iter` and `get` hand the adapter the type it works with.
`DecodeError<P>` carries the rule's problem in `Path`. The git adapter
passes `TreeRule`, whose three functions are `TreePath::parse`,
`TreePath::is_repository_metadata` and `TreePath::as_bytes`, and
re-exports `Workspace` and `DecodeError` as aliases under it, so its
callers keep their names. The sandbox adapter will pass a rule that
delegates the same way. A test in each adapter pins its rule to
`TreePath` byte string by byte string (`git_cli_rule_is_tree_path` for
the git adapter), so the two adapters cannot drift apart from each other
or from the core.

**Order is by bytes, never by the rule's type.** The map is keyed by the
path's bytes (`PathRule::bytes`), compared as bytes. The canonical
encoding, the ancestor check and the directory lookups depend on byte
order (ADR-010, D2), and with this key no rule's `Ord` can change them;
`TreePath`'s order is byte order anyway (ADR-018, D1), so for the git
adapter nothing changes. `decode` also checks order on the bytes it
keeps, the rule's `bytes` of the parsed path, so the map and the checks
see the same bytes.

**`materialize` takes a `Metadata` mode.** `Metadata::Refuse` refuses
repository metadata, in entries and gitlinks alike, before anything is
written: the git adapter passes it, which is the behavior before the
move. `Metadata::Carry` writes metadata like any other entry: the
sandbox passes it. Every other check, the node cap, the gitlink checks,
the parent check, `create_new` and the explicit modes hold in both
modes. `Carry` is only for copying into a sandbox a snapshot whose
repository metadata the runner generated, never for a tree the agent
wrote: on a host directory where any git runs, an agent's `.git/config`
or `.git/hooks` (`core.fsmonitor`, a hook) would run as the runner user.
Every tree read back from a sandbox goes through `Refuse` or drops its
metadata first.

**A test seam for `insert`.** `Workspace::insert` looks every ancestor
up, which costs O(depth × length) per path (ADR-010, D2, review of #30
part 2), so it was test-only. The git adapter's own unit tests build
small workspaces with it, so it is built under the crate's tests and
under the feature `test-seam`, which the adapter enables from
`[dev-dependencies]` only; resolver 3 keeps the feature out of normal
builds, as for `boneli-private-dir` (ADR-030, D4).

Why not `boneli-app`: the codec alone would fit the core, but
`materialize` writes files, which the core cannot (ADR-001), and it uses
the codec's internal walks (`new_directories`, `implies_directory`).
Splitting the two across crates would make those walks public API.

Why not `boneli-sys`: the reasons of ADR-021, D1. It is the one crate
where `unsafe` compiles, and it carries a `compile_error!` for anything
but little-endian Linux on x86_64 and aarch64; the git adapter would
link the sandbox runtime for code that needs no syscall wrapper.

Language: Rust. The code being moved is Rust, and a workspace member
cannot be anything else.

### D2. The port's shape: pods, pod limits, workspace exchange, layers

ADR-004 (D11) left the `Sandbox` port minimal: one root filesystem, a
per-command `Limits { wall_ms, memory_bytes, processes }`, `exec`,
`copy_out` and `destroy`, and no way to copy a workspace in or export
one. #8 needs a pod (the agent's container next to PostgreSQL or Redis,
which talk over loopback), the workspace exchange, the dependency layers
of the prepare phase and the phase rules of ARCHITECTURE "Isolation".
The extension rule of ADR-004 (D1) lets #8 add operations and clauses;
this decision records them, and ADR-004 stays as it is. The port lives
in `boneli-app` (`src/sandbox.rs`), so it is pure: no new crate, no
dependency.

**The spec.**

```rust
SandboxSpec {
    phase,
    containers: Vec<ContainerSpec { name: ContainerName, rootfs }>,
    workspace: WorkspaceBytes,
    dependencies: Vec<LayerRef>,
    brokers: Vec<Broker { name: BrokerName, socket: String }>,
    limits: PodLimits,
    user: u32,
}
PodLimits { memory_bytes, processes, cpu_millis, workspace_bytes,
            workspace_inodes, tmp_bytes, shm_bytes }
Limits { wall_ms, output_bytes }
```

The first container holds the workspace, the dependencies and the
brokers; the others (a database, a cache) get their own root, `/tmp` and
`/dev/shm`. `Command` gains `container`, the name it runs in.

- **Memory and the process count move to the pod.** The cgroup is the
  pod's: ADR-007 (D8) has one keeper per cgroup, no sub-cgroups and
  `memory.oom.group` over the whole tree, so a per-command memory limit
  would need a cgroup per command that the keeper does not watch. What
  stays per command is what only a command has: its wall time and its
  output.
- **`output_bytes`** bounds each of the two streams. One byte more kills
  the command and fails the exec, so a cut transcript is never returned
  as a whole one; the verifier would otherwise judge test output it did
  not see. **`ExitStatus::TimedOut`** is the wall limit's own status: a
  `Signal(9)` would look like the workload's own kill.
- **Copy-in is a spec field, not an operation.** Dependency layers are
  bound under `/workspace` after the copy-in and before `pivot_root`,
  while the host paths are still visible (D3), so the workspace must be
  there before the first process runs. An operation would need a running
  pod, and then the mounts would come after it.
- **`WorkspaceBytes`** prints only its length in `Debug`: the bytes are
  the customer's code, and a spec lands in failure details and logs.
- **Names.** `ContainerName` is an RFC 1123 label,
  `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, and not `localhost`. It becomes
  the UTS host name and an alias in every `/etc/hosts` of the pod (compose
  files address services by name), so the grammar is also what keeps a
  name from adding a line to those files; 63 is the label limit of
  RFC 1123, and a longer name is no host name. `BrokerName` is
  `[a-z][a-z0-9-]{0,30}`, bound at `/run/boneli/<name>.sock` for the shim
  (#9). The 31 bytes are a choice, not a measurement: the path then has
  at most 48 bytes. The hard ceiling is 90, the 108 bytes of `sun_path`
  minus `/run/boneli/` (12), `.sock` (5) and the NUL; above it the shim's
  `connect` fails. The grammars are ASCII and checked byte by byte, so a
  Cyrillic look-alike, a zero-width or blank character, upper case and a
  newline are all refused.

**The pod relations are one core function.** `PodLimits::check(n)`, with
`n` the number of containers, refuses:

- `n = 0`;
- any size of 0: for a tmpfs, 0 means unlimited (ADR-007);
- `workspace_bytes + n × (tmp_bytes + shm_bytes) > memory_bytes`, or a sum
  past 2^64. Every writable file system of the pod is a tmpfs charged to
  the pod's `memory.max` (D4); a tmpfs cap above `memory.max` never fires
  before the OOM kill, so it would bound nothing;
- `processes < n + 2`. Each container's anchor (D3) is one task for the
  pod's life, and an exec needs two while it starts: the joining process
  and the program it clones. With `n + 1` the first exec cannot start;
- `cpu_millis < 10`. `cpu.max` is `cpu_millis × 100` µs over a period of
  100,000 µs (the kernel default; measured on the dev host: a fresh
  cgroup reads `max 100000`), and the kernel refuses a quota below
  1,000 µs (ADR-007, D8). With 9 the write of `cpu.max` fails at setup.

`SandboxSpec::check` adds what else needs no file system: unique
container, broker and layer names, broker sockets that are absolute paths
without NUL, no broker in a `Verify` sandbox, and a user other than
4,294,967,295, `(uid_t)-1` (ADR-007, D1). Both adapters call it first in
`create`, so they cannot disagree on what a valid pod is. There is no cap
on the number of containers: the bound is `processes`, and the runner's
descriptors, past which `lease` already fails closed (ADR-025, D2).
`overlapping_paths` finds two dependency paths that are equal or nested
(`node_modules` and `node_modules/x`); both adapters use it in `seal`,
and over the paths of all layers of a spec in `create`.

**New operations.**

- `start(id, &Command)`: a service. It runs until `destroy`, and its
  output is discarded; a service that dies fails the pod at the next
  operation (D8).
- `export(id) -> Vec<u8>`: the workspace in the `Git` adapter's snapshot
  format, without the dependency mounts. `Git::diff` takes it.
- `seal(id, &[RelativePath]) -> LayerRef`: copies these directories of a
  `Prepare` sandbox into a new layer. Any other phase, no path and two
  paths that overlap are refused.
- `release(&LayerRef)`: removes a layer. A layer a live sandbox mounts is
  refused, because deleting it under a live bind would empty that pod's
  dependencies (D6).

Every refusal is `SandboxError::Failed` with a detail. No error variant
is added: nothing a caller does differs between the refusals, each of
them is a bug in the caller's spec or a host problem, and the detail
names which. `UnknownSandbox` stays the one handle error, also for
`start`, `export` and `seal` on a destroyed sandbox.

**Phase rules.** A `Verify` spec with any broker is refused (ARCHITECTURE:
verification runs "without either socket"), and only a `Prepare` sandbox
can be sealed. A layer is the one thing that travels from one sandbox
into another, so with this rule nothing the agent wrote can become a
layer the verify sandbox mounts (invariant 6).

**The contract** grows from 7 to 24 clauses; each new one has its own
mutant in `boneli-replay-check`, and the mutant table stays a bijection
(79 clauses, 96 mutant cases over all ports):

| Clause | What it requires | Mutant |
| --- | --- | --- |
| `unknown-container` | an exec or start in a container the pod does not have is `Failed`; an exec in the second container runs there, and a `write` there leaves the workspace as it was (`copy_out` `NotFound`, export unchanged) | `IgnoresContainer`: runs it in the first |
| `limits-checked` | a two-container spec with 3 tasks, memory one byte below the storage sum, `cpu_millis` 9, a `tmp_bytes` of 0, the user 4,294,967,295, two containers of one name, two brokers of one name, or a broker socket that is relative or holds NUL is `Failed` | `UncheckedLimits`: creates with generous limits |
| `output-cap` | output of exactly `output_bytes` is returned whole, one byte more is `Failed`, on the standard and on the error output | `TruncatesOutput`: cuts it and returns it |
| `start-runs` | what a started service writes is in the workspace once the fixture's `settle` command returns | `StartIgnored`: runs nothing |
| `export-round-trip` | a sandbox created from a workspace holds its file and exports that workspace byte for byte | `ExportEmpty` |
| `export-sees-write` | after `write`, the export is the workspace with the file set | `ExportStale`: exports the workspace it was created from |
| `copy-out-no-symlink` | `copy_out` through a symlink at the path or at a parent, each to a planted file outside the workspace, and through a link at the path with a relative target inside the workspace, is `Failed` | `FollowsLinks` |
| `verify-without-brokers` | a `Verify` spec with a broker is `Failed`, an `Agent` spec with it is created | `VerifyKeepsBrokers`: creates it as `Agent` |
| `seal-prepare-only` | sealing an `Agent` or `Verify` sandbox is `Failed`, a `Prepare` one is sealed | `SealsAnyPhase`: creates every sandbox as `Prepare` |
| `seal-no-symlink` | with a symlink at the sealed file or at the sealed directory, or a link at the file with a relative target inside the workspace, the seal is `Failed` or gives a layer whose file is not the planted one | `SealFollowsLinks`: copies the planted file in |
| `sealed-layer-mounted` | a sandbox with the layer reads the sealed file, as it was at the seal, after the sealed sandbox wrote again and was destroyed; a sandbox without it reads nothing, and the copy target is empty before the read | `DependencyNotMounted`: drops the dependencies |
| `dependency-read-only` | after a write beneath the mount in an `Agent` sandbox, that sandbox and a `Verify` sandbox with the same layer read the sealed content | `LayerWritable`: the write reaches the layer |
| `export-without-mounts` | the export of a sandbox that mounts a layer is the workspace it was created from | `ExportsMounts`: walks into the mount |
| `dependency-overlap-refused` | a spec that lists one layer twice, or two layers sealed from one directory, is `Failed` | `IgnoresOverlap`: mounts the last over the others |
| `distinct-layers` | three seals give three handles, two of them of the same sandbox | `ReusesLayer` |
| `released-layer-unknown` | after `release`, a spec naming the layer and a second release are `Failed` | `ReleaseIgnored`: reports success, keeps it |
| `layer-in-use-kept` | `release` of a layer a live sandbox mounts is `Failed`, the sandbox still reads it, and after `destroy` it is released | `ReleasesInUse` |

Three of ADR-004's clauses are stronger: `isolated` and
`fresh-after-destroy` also require the other sandbox's export to equal
the workspace it was created from, so a write that leaked into another
sandbox's export is caught and not only one that leaked into its
`copy_out`; `destroyed-is-unknown` also covers `start`, `export` and
`seal`.

Review of part 2 (run 1) showed broken adapters that passed the first
version of 18 clauses; each now fails a clause, and six of them stay in
the table as regression mutants: `KnownInFirst` (a known container's
command runs in the first) fails `unknown-container`, `LimitsOnly` (an
adapter that calls `PodLimits::check` and not `SandboxSpec::check`) fails
`limits-checked`, `FollowsRelativeLinks` fails `copy-out-no-symlink`, and
`LayerFollowsSource` (a layer that is a live view of its sandbox),
`LayerDiesWithSource` (a layer that dies with it) and `MountsAll` (every
layer in every sandbox) fail `sealed-layer-mounted`. Run 2 added
`SealFollowsRelativeLinks` (a host-side copier follows a relative link,
which resolves there as it does inside) to `seal-no-symlink` and
`ErrorOutputUncapped` to `output-cap`, and the clause
`dependency-overlap-refused`. A layer listed twice is no variant of
`limits-checked`: it overlaps itself, and that clause, which seals real
layers, checks both refusals; a spec check of its own could not be told
apart from the overlap check. The wall limit has no clause yet: no
in-memory program runs long, and part 5 adds the clause with the adapter
that kills at `wall_ms` (D8).

`copy-out-no-symlink` closes what ADR-004 (D11) left to #8. It requires
`Failed`, not `NotFound`: an adapter cannot report a refused symlink as a
missing file, and a fixture whose `link` command planted nothing fails
the clause instead of passing it. Its relative link points to a sentinel
inside the workspace, which the container and the host resolve to the
same bytes, so an adapter that follows links where the absolute targets
do not resolve (on the host, as the runner user) shows too. A seal is
not required to refuse every link: D6 carries links in a layer raw, so
`seal-no-symlink` requires only that the planted file never reaches the
layer. The fixture brings what only the adapter's test knows: a second
container, commands that plant a file outside the workspace and link to
it at the path and at a parent, one that links the path to a sentinel by
a relative target, a broker, a dependency directory that the path lies
beneath, a command that copies the path out of a mounted layer to a path
outside it (the real adapter's `copy_out` does not cross a mount, D5), a
command that writes other content over the path, two that print known
output, one on each stream, and a service with a command that waits until the service has
written. Like the `Git` suite, `run` takes an `edit` hook over the
adapter's snapshot format. Fixture guards turn the vacuous cases into
violations: empty planted content, an `edit` that changes nothing, a
second container whose name the spec already uses, a path not beneath
the dependency, a copy target inside it, overwritten content equal to
the content, and empty printed output.

**The in-memory adapter.** `MemorySandbox` reads and writes the workspace
in `MemoryGit`'s packed tree format. A scripted `Program` now writes
`Write::File` or `Write::Symlink` at workspace paths, files outside the
workspace by absolute path (`outside`, for `plant`) and copies from an
absolute path, a mounted layer included, into the workspace (`copies`,
for `read`). Writes replace and never follow, and only a run in the
first container reaches the workspace. `copy_out` refuses a symlink at
the path or at a parent and a path beneath a mount. The packed format
holds files only, so an export of a workspace with a symlink is
`Failed`, never a tree with the link dropped. It checks what needs no
process: `SandboxSpec::check`, the workspace format, known layers and
their paths, that no dependency path lies at or above a file of the
workspace, the workspace's inodes (every file, directory and mount point,
and the root), the seal phase and the output cap. `entry` shows what a
program left at an absolute path, without following anything, as
`commands` shows what ran; the `FollowsLinks` mutant follows links with
it.

Rejected:

- **A copy-in operation.** See above: the mounts must come after the
  copy-in and before `pivot_root`.
- **Keeping memory and processes per command.** It needs a cgroup per
  command, which ADR-007 (D8) excludes, or limits that look per command
  and are the pod's.
- **One root filesystem per sandbox and a service as a second sandbox.**
  Two sandboxes do not share loopback, and the agent's tests reach
  PostgreSQL on 127.0.0.1:5432.
- **New error variants for every refusal** (`UnknownLayer`, `LayerInUse`,
  `WrongPhase`). No caller branches on them yet; the extension rule can
  add one when a caller does.

## Consequences

- `boneli-workspace` is on the always-review list (decided at #8 STOP 1):
  it writes agent-controlled data onto the host for the git adapter, and
  it is the sandbox's copy-in.
- `boneli-git-cli`'s public API changes shape, not behavior: `Workspace`
  and `DecodeError` are aliases over the generic types, and
  `materialize` takes a fifth argument, the `Metadata` mode. No crate in
  the workspace calls it but the adapter itself.
- A rule that breaks the contract of `PathRule` (a path that is empty,
  absolute or has an empty, `.` or `..` component, or `bytes` that differ
  from what `check` accepted) makes `decode` and `encode` disagree for
  that rule. The crate cannot check that for every rule; each adapter's
  pin test does it for its own.
- The crate's unit tests cannot use `TreePath`, so they run under a copy
  of the tree path rule in `src/test_rule.rs`. It is test-only; the pin
  tests in the adapters hold the real rules to the core.
- The `Sandbox` port changes shape (D2) with no production consumer yet:
  the ripple is the contract suite, `boneli-memory` and the mutants. A
  caller that sized memory per command now sizes the pod, and has to fit
  the storage sum of D2 into `memory_bytes`; all pod storage is memory
  (D4, STOP 1 decision 1).
- Until part 5 lands, the suite runs on `MemorySandbox` and the mutants
  only; the real adapter must pass the same 24 clauses on the host.
- The in-memory adapter cannot export a symlink: its snapshot format
  holds files only. No clause exports one, and the real adapter carries
  symlinks raw (D5).

## Alternatives considered

- **The rule as a value, a validator over bytes** (as ADR-010 put it, and
  as `boneli-private-dir` takes `text_rule`, ADR-021 D2), with paths kept
  as a byte type of this crate. Every call site in the git adapter that
  reads a path (`patch_between`, the look-alike checks of `diff`, the
  gitlinks it passes in) would turn the bytes back into a `TreePath` with
  a parse that cannot fail, each with an error arm or an `expect`.
  Rejected: the associated type keeps the adapter's type and removes
  those arms.
- **Keyed by the rule's type, ordered by its `Ord`.** It needs no key
  type, but the canonical encoding and the range lookup behind the node
  cap and the gitlink checks would then rest on an `Ord` the crate does
  not see. Rejected for the byte key above.
- **A copy of the codec in the sandbox adapter.** Two copies of a
  parser on the security boundary; ADR-021 records what a fix that lands
  in one copy costs. Rejected.
- **`Metadata` as a property of the rule.** The rule says what metadata
  is; whether to write it is the caller's choice, and both adapters use
  the same rule. Rejected.

## Accept when

Part 6 of #8 merges: the sandbox adapter passes the `Sandbox` contract
suite on the host and the real-image pod acceptance is green on both
architectures, with this ADR's later decisions added by the parts that
implement them.
