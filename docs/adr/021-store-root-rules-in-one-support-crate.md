# ADR-021: The store-root rules live in one support crate

- Status: accepted
- Date: 2026-11-20

## Context

`boneli-oci` (ADR-009, D8) and `boneli-store-fs` (ADR-012, D1) keep their
data under a root on the host, as the runner user, and reach it by path
in every later call. Both apply the same root rules: an absolute path
without a `.` or `..` component, created `0o700` where it is missing,
resolved, a directory owned by the caller with no group or other
permission bits, and ancestors that pass sshd's `StrictModes` rule. Each
crate held its own copy, because an adapter cannot depend on another
adapter (rule `graph-adapter`, ADR-001). ADR-012 D1 recorded the
duplication as a known limit and named #66 to remove it.

The duplication already cost one round trip. The review of #67 found a
hole in `boneli-store-fs`'s copy: `<d>/missing/../gw/store` was checked
at `<d>` and created under a group-writable `gw`. The fix (the `.` and
`..` rule) had to be made twice, and it sat in the *sequence* of `open`,
not in the three helpers (`own_uid`, `private_dir`, `check_ancestors`)
that ADR-012 D1 named as the copies. A fix that lands in one copy and
not the other is a hole in an always-review crate that no test of the
other crate sees.

One more weakness is in the sequence itself. A missing root was created
through the path as given, after its existing ancestors were checked on
their resolved path. Two things follow:

- If an ancestor is a symlink to a name the overlay rule refuses
  (`<d>/link -> <d>/real:dir`), `boneli-oci` created `real:dir/store` and
  only then refused the resolved root. The refusal was right; the empty
  directory stayed.
- If an ancestor link is re-pointed between the check and `mkdir`, the
  root is created where the check never looked.

## Decision

### D1. A support crate, `boneli-private-dir`

The rules move into a new std-only support crate, `boneli-private-dir`,
listed in `roles.support` of `tools/architecture.toml`. Both adapters
depend on it. It has no dependencies: the rules need `std::fs` and the
Unix `MetadataExt` and `DirBuilderExt` extensions, nothing else, so the
new crate adds no external edge to either adapter's graph.

It reads the caller's uid as the owner of `/proc/self`, as both copies
did: `#![forbid(unsafe_code)]` crates cannot call `geteuid`, and this ADR
moves code, it does not change what it reads.

Why not `boneli-sys`: it is the one crate where `unsafe` compiles (about
7,000 lines, the sandbox runtime of ADR-007), and it carries a
`compile_error!` for anything but little-endian Linux on x86_64 and
aarch64. Every file-backed adapter would then link the
sandbox runtime for a check that needs no syscall wrapper. Inside
`boneli-sys`, a reviewer would also rightly replace `/proc/self` with
`geteuid`, a behavior change that does not belong in an extraction.

Language: Rust. The code being moved is Rust, and a workspace member
cannot be anything else.

### D2. The API and the sequence

```rust
pub fn prepare_root(
    root: &Path,
    text_rule: &dyn Fn(&Path) -> Result<(), &'static str>,
) -> Result<PathBuf, Error>;
pub fn create(dir: &Path) -> Result<(), Error>;
pub enum Error { Rule { path, reason }, Io { path, source } }
```

`prepare_root` runs, in this order, with the reason texts of both copies
unchanged:

1. not absolute → `Rule`, "must be an absolute path";
2. a `.` or `..` component, on the path's bytes split at `/` (because
   `Path::components` drops every `.` but a leading one) → `Rule`;
3. `text_rule` on the root as given → `Rule` with its reason;
4. the caller's uid (owner of `/proc/self`);
5. if the root does not exist: the deepest existing ancestor is
   resolved and checked with every ancestor above it; the root is created
   at that resolved ancestor joined with the missing names, once that
   path passes `text_rule` (D3);
6. the root is resolved and passes `text_rule`;
7. a directory, owned by the caller, with no group or other bit;
8. every ancestor of the resolved root passes the ancestor rule;
9. the resolved root is returned.

The text rule is the caller's: `boneli-oci` passes its overlay rule
(UTF-8, none of `,`, `:` and `\`, which overlay mount options use as
separators and escapes; ADR-007, D7), `boneli-store-fs` passes none. A
flag for the overlay rule inside the shared crate would put mount
knowledge into generic plumbing.

`create` makes a directory and its missing parents `0o700` and accepts
one that exists; both adapters create their subdirectories with it.

The ancestor rule is a pure function over the facts of one ancestor
(is a directory, owner, `st_mode`, is `/`) and the caller's uid, so its
arithmetic is table-tested without root and without `chmod`, which may
drop setgid and setuid bits on a real directory. A filesystem walk
applies it from the resolved directory up, so the deepest offender is
reported.

The numbers, each with its own reason:

- **`0o700` on created directories:** only the runner user reads or
  writes a store. Run logs hold ticket text, blobs hold the customer's
  code, and layers are what a sandbox runs. Any group or other bit
  would hand one of those to another local user.
- **`mode & 0o077 != 0` refuses the root:** every one of those bits is
  access by someone other than the owner, and the store cannot tell a
  group that is only the caller from a shared one.
- **`mode & 0o022 != 0` refuses an ancestor:** write permission on a
  directory is permission to rename its entries, and renaming an entry
  on the path is swapping the root after it was checked. Read and
  execute bits (`0o055`) only let others look, which the private root
  itself prevents.
- **`0o1000` (sticky) exempts an ancestor from that:** in a sticky
  directory only an entry's owner (or the directory's) may rename it, and
  the ancestor rule requires the next entry down to be root's or the
  caller's. That is why `/tmp` (`1777`) is a valid ancestor.
- **The owner rule (root or the caller):** the owner of a directory can
  chmod it at any time, so a directory owned by a third user is as good
  as writable by them. `/` is exempt from the owner rule but not from the
  mode rule: whoever owns `/` owns every path on the host, and in a user
  namespace `/` shows the overflow uid (65534).

### D3. A missing root is created where it was checked

Step 5 creates the root at its *prospective resolved path*, not through
the path as given, and runs the text rule on that path first. For every
input without a concurrent change on the filesystem, the result (the
returned path, or the error's variant and reason) is the same as the
copies gave, and so is the error's path, with one exception: an `Io`
error from creating the root names the prospective resolved path, not
the path as given (`<d>/file/` reports `<d>/file`). No consumer matches
on that path. Two side effects go away:

- A root whose resolved path the text rule refuses is refused before it
  is created, so `<d>/link -> <d>/real:dir` leaves `real:dir` empty.
- An ancestor link re-pointed between the check and `mkdir` cannot
  redirect creation: the directory is made where the check looked, and
  the later resolution of the given path, which now points elsewhere,
  fails as an `Io` error or is checked again in steps 6 to 8.

Creating each missing component through a directory descriptor would
close the remaining window between resolving the ancestor and `mkdir` as
well; ADR-009 D8 rejected descriptor-relative roots for now, and that
rejection stands. The race that remains needs write access to an
ancestor that has just passed the ancestor rule, so it is no wider than
the rule itself.

### D4. Tests and mutants

The matrix both crates pinned moves into the shared crate's tests, with
one test per edge case of the #66 plan: empty and relative paths, `/`
and `//`, doubled and trailing slashes, dot look-alikes and blank or
non-UTF-8 names as plain names, NUL bytes and 256-byte names as `Io`
errors, dangling and symlinked ancestors, a file as an ancestor, an
unsearchable parent, the text rule's order and refusals, the re-pointed
link of D3, missing intermediates, eight concurrent first opens, an
ancestor owned by another user (`/proc/<pid>` of a process of another
user) and a POSIX ACL write grant (the ACL mask shows in the group bits).
Both adapters keep their five root tests unchanged, as wiring tests, and
each gains one test that pins the error mapping of D5.

Seven mutants of the shared crate (the sticky exemption, the check
before creation, the dot rule, the text rule after creation, the mode of
created directories, the owner rule, the owner exemption of `/`) are
each killed by named tests; the PR records which. Four of them also
fail the tests of both consumers, which shows neither keeps a private
copy.

### D5. Errors map privately

Each adapter maps `boneli_private_dir::Error` into its own error type in
a private function: `Rule` becomes `boneli-oci`'s `Error::Root` and
`boneli-store-fs`'s `OpenError::Root`, `Io` becomes `Error::Cache` and
`OpenError::Io`. A public `From` impl would put the support crate into
both adapters' public APIs. The `Display` text of a refused root is
unchanged.

## Consequences

- The root rules exist once. ADR-012's known limit "The root rules exist
  twice until #66" is closed by this ADR; ADR-009 and ADR-012 keep their
  text otherwise.
- `boneli-private-dir` is on the always-review list (decided at #66
  STOP 1): a bug in it is a security bug in `boneli-oci` and in
  `boneli-store-fs`.
- A root under a symlinked ancestor is now created under the link's
  target directly (D3); a root the text rule refuses after resolution
  leaves no directory behind.
- `boneli-git-cli` keeps its own `private_dir`: its `open` creates a new
  directory non-recursively and refuses one that exists (ADR-010), and
  its root has no ancestor check. Whether it should adopt these rules is
  #85. `boneli-forge-github` keeps its three-line `own_uid` as part of
  the key-file rule of ADR-014, which checks no ancestor by decision.
- The skip-prone tests (another user's process, ACLs, `/usr` as root)
  print `skipped` where the host cannot run them; the pure ancestor table
  covers the same rules on every host.

## Alternatives considered

- **`boneli-sys`:** rejected in D1 (the `unsafe` crate, the platform gate,
  and the pressure to change `/proc/self` to `geteuid`).
- **Keeping two copies:** the review of #67 showed a fix landing in one
  and the other needing it too; nothing but discipline keeps them equal.
- **Sharing the source with `include!` or `#[path]`:** banned by ADR-001
  ("Complete file set"): the checks must see every file a crate compiles
  inside its own package.
- **Extracting only the three helpers:** the #67 fix sat in the sequence
  of `open`, which would still exist twice.
- **An overlay flag in the shared crate:** puts mount knowledge into
  generic plumbing; the caller's text rule (D2) carries it instead.
- **Descriptor-relative roots** (`openat` and friends on a held root
  descriptor): rejected by ADR-009 D8 for now (`openat`,
  `mkdirat`, `renameat` and `unlinkat` wrappers would be new `unsafe` in
  `boneli-sys`); D3 takes the part that needs no descriptor.
