# ADR-042: The Linux sandbox adapter: pods, workspace exchange and fail-closed outcomes

- Status: proposed
- Date: 2026-11-28

## Context

#8 builds `boneli-sandbox-linux`, the real adapter of the `Sandbox` port
on the runtime of ADR-007. It lands in six pull requests, and this ADR
grows with them: each PR adds the decision it implements, and the last
one accepts the ADR. This revision holds D1, from part 1.

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
