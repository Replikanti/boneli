# ADR-024: The git adapter's root under the ancestor rule

- Status: accepted
- Date: 2026-11-20

## Context

`GitCli::open` (ADR-010, D7) creates the adapter's root with mode 0700
and checks nothing above it. Every later call reaches the root by path:
git gets `--git-dir` inside `<root>/stores/`, the runner's `HOME` is
`<root>/home`, `diff` names the store's objects in
`GIT_ALTERNATE_OBJECT_DIRECTORIES` and writes the agent's workspace into
`<root>/scratch/<n>` before `git add -A` reads it back. A local user who
can rename an entry of an ancestor of the root can therefore swap the
root after `open`. They can then read the customer's code in the stores
and scratch directories, and change the files `diff` writes into
`scratch/<n>` between the write and `git add -A`. The diff, and with it
the pull request the runner pushes under its token, then carries their
content.

This is the class the review of #60 reproduced for the OCI store under a
`0o777` parent. `boneli-oci` and `boneli-store-fs` close it with the
StrictModes ancestor rule of ADR-009 D8, which ADR-021 moved into the
support crate `boneli-private-dir`. ADR-021's Consequences left the git
root out and named #85 to decide it.

The git root has a different contract from a store root. A store root
may exist and is reopened (`prepare_root` accepts an existing private
root and creates missing parents). The git root must not exist before
`open` (ADR-010, D7), because one adapter owns the tree: its `next_dir`
counters start at 0 on every `open`, and the adapter never removes a
store (ADR-010, Consequences), so two adapters on one root would write
into each other's directories.

## Decision

### D1. The git root adopts the ancestor rule

`boneli-private-dir` gets a second entry point, `create_new_root`, which
applies the rules of ADR-021 to a root that must not exist yet.
`GitCli::open` creates its root through it, before git runs, and keeps
the path it returns for every later call. The subdirectories of the root
(`home`, `stores`, `scratch`, `tmp` and the fresh directories under
them) keep git-cli's own `private_dir`: they sit under the checked
`0o700` root, which only the runner can rename entries of.

Language: Rust, because both crates are Rust workspace members.

### D2. The API and the sequence

```rust
pub fn create_new_root(
    root: &Path,
    text_rule: &dyn Fn(&Path) -> Result<(), &'static str>,
) -> Result<PathBuf, Error>;
```

It runs, in this order, with the reason texts of `prepare_root`:

1. not absolute → `Rule`, "must be an absolute path";
2. a `.` or `..` component → `Rule`;
3. `text_rule` on the root as given;
4. no parent or no name (`/`, `//`) → `Io` of kind `AlreadyExists` at
   `/`, without touching the filesystem;
5. the caller's uid (the owner of `/proc/self`, ADR-021 D1);
6. the parent is resolved; an error is `Io` at the parent;
7. the resolved parent and each of its ancestors pass the ancestor rule;
8. the prospective root is the resolved parent joined with the root's
   name, and passes `text_rule`;
9. one non-recursive `mkdir` with mode `0o700` there; `EEXIST` is `Io`
   of kind `AlreadyExists` at the prospective root;
10. an explicit `chmod 0o700`;
11. the prospective root is returned.

There is no re-check after `mkdir`: in a parent that passed the rule,
only root or the caller can rename the new entry. `prepare_root` and
`create` are unchanged, so `boneli-oci` and `boneli-store-fs` see no
change.

`GitCli::open` passes no text rule: a root may hold `:` and `#`, which
the adapter already C-quotes where git would read them as separators
(ADR-010, D4).

The rules and their numbers, each with its reason here:

- **`0o700` on the root:** the root holds the customer's code (the
  stores), the working directories of `diff`, and the `HOME` of calls
  that carry the git token. Any group or other bit hands one of those to
  another local user.
- **The explicit `chmod`:** `mkdir` applies the umask, and ADR-010 D7
  states the mode, not the mode under some umask. Under `umask 277`, a
  plain `mkdir 0o700` gives `0o500`, and the adapter could not create its
  own subdirectories.
- **`mode & 0o022` refuses an ancestor:** write permission on a directory
  is permission to rename its entries, and renaming an entry on the
  root's path is swapping the root. Read and execute bits (`0o055`) only
  let others look, and the `0o700` root stops them one level down.
- **`0o1000` (sticky) exempts an ancestor:** in a sticky directory only
  the entry's owner, the directory's owner or root may rename an entry,
  and the next entry down must be root's or the caller's. That is why a
  root directly under `/tmp` (`1777`, owned by root) is valid.
- **The owner rule (root or the caller):** the owner of a directory can
  `chmod` it at any time, so a directory owned by a third user is as good
  as writable by them.
- **`/` is exempt from the owner rule, not the mode rule:** whoever owns
  `/` owns every path on the host, and in a user namespace `/` shows the
  overflow uid (65534).
- **Non-recursive `mkdir`:** it is what makes the root exclusive. Of two
  callers racing on one missing root exactly one gets the directory, and
  a root that exists in any form (a directory, a file, a symlink, a
  dangling one) is refused without following it. A missing parent stays
  an `Io` error of kind `NotFound`, as before: the parent is the
  operator's configuration, and creating it would make directories nobody
  asked for, under ancestors whose ownership the operator never chose.
- **Created under the resolved parent:** the directory is made where the
  ancestor check looked, not through the given path again, so a link on
  the path re-pointed after the check cannot redirect it (ADR-021, D3).
  Every later call uses that resolved path, so re-pointing the link after
  `open` changes nothing the adapter reads or writes.

### D3. Errors map privately

`GitCli::open` maps `boneli_private_dir::Error` in a private function:

- `Rule` becomes the new `OpenError::Root { path, reason }`, shown as
  `adapter root <path>: <reason>`;
- `Io` of kind `AlreadyExists` becomes `OpenError::RootExists`, whose
  meaning is unchanged;
- any other `Io` becomes `OpenError::Io` with the same kind and a message
  that names the path.

There is no `From` impl, so the support crate stays out of git-cli's
public API (as ADR-021, D5 does for the other two consumers). The support
crate's `Error` gets no `Exists` variant: both other consumers map it
exhaustively, and the variant would exist for one entry point only; the
io kind carries "exists" instead.

### D4. Tests and mutants

`crates/boneli-private-dir/tests/root.rs` gets one test per edge case of
the #85 plan: the ancestor modes with the deepest offender reported and
an existing root refused by the rule before `AlreadyExists`; every form
of an existing root, `/` and `//`; eight threads racing on one root
(exactly one wins); creation at the checked path when a link is
re-pointed during the check; the text rule's order and refusals; dot
components; relative, look-alike, blank, non-UTF-8, NUL and over-long
names; parent errors (missing, dangling link, link loop, file, no write
permission); symlinked ancestors; another user's `/proc/<pid>` as an
ancestor; and the mode under `umask 277` in a child process.
`crates/boneli-git-cli/tests/boneli_git_cli_tests/open.rs` gets seven
wiring tests; each refusal also shows that no git ran, and one test
re-points a link after `open` and runs `fetch_base`, `snapshot` and
`diff`, which leave the link's new target empty.

Nine mutants are each killed by named tests; the PR records which:
skipping the ancestor check, a recursive `mkdir`, `mkdir` through the
given path, no dot rule, no explicit `chmod`, no text rule on the
prospective root, the ancestor walk on the unresolved parent, git-cli
keeping the configured root, and git-cli mapping `AlreadyExists` to `Io`.
The first, second, fourth and seventh also fail git-cli's tests, which
shows that git-cli keeps no private copy of the rules.

## Consequences

- `GitCli::root()` returns the root as created, under the resolved
  parent, which differs from the configured root when an ancestor is a
  symlink.
- A root with a `.` or `..` component is refused.
- A regular file as the parent is `OpenError::Root` ("must be a
  directory"), no longer an `ENOTDIR` `Io` error.
- A root under a group-writable directory is refused even when the group
  is the runner's own (a `umask 002` host), as for store roots. Test hosts
  with `umask 002` have a group-writable `target/`, and every git-cli test
  that opens an adapter fails there with `OpenError::Root`, naming the
  directory and the rule; the `boneli-private-dir`, `boneli-oci` and
  `boneli-store-fs` suites already have the same exposure. CI and the
  development hosts use `022`.
- The integration tests resolve their temporary directory, because a
  relative `CARGO_TARGET_DIR` puts `..` into `CARGO_TARGET_TMPDIR`.
- `boneli-private-dir` becomes a security dependency of `boneli-git-cli`;
  both are on the always-review list.
- Residual: between resolving the parent and `mkdir`, a rename needs
  write access to an ancestor that has just passed the rule, so the
  window is no wider than the rule itself (ADR-021, D3).
- ADR-010 keeps its text; this ADR adds the ancestor rule to its D7.

## Alternatives considered

- **A public ancestor-only check, with git-cli keeping its own `mkdir`
  through the given path:** leaves a second copy of the sequence, and the
  hole the review of #67 found sat in the sequence, not in the helpers. It
  also leaves the re-pointed-link window of ADR-021 D3 open.
- **An existence check followed by `prepare_root`:** `prepare_root`
  accepts an existing private root by design and creates missing parents
  recursively, so two adapters racing on one root would both open, which
  breaks the "must not exist" contract of ADR-010 D7.
- **No check, recorded as not needed:** the root is reached by path in
  every call, so its ancestors decide who can swap it (Context).
- **A descriptor-relative root:** ADR-009 D8 rejected it (new `unsafe`
  wrappers in `boneli-sys`), and here it would also not help: git
  receives paths (`--git-dir`, `HOME`, the alternates variable), not
  descriptors.
- **A new `Error::Exists` variant in the support crate:** rejected in D3.
