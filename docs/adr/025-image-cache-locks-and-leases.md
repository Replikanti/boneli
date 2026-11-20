# ADR-025: Locks and leases in the OCI image cache

- Status: proposed
- Date: 2026-11-20

## Context

The OCI image store of ADR-009 only grows. #56 adds eviction: layers
nobody uses go once the store passes a byte budget. Before anything is
removed, the store has to know what is in use, and by whom:

- **A layer under a running sandbox.** The sandbox mounts the layer
  directories as overlayfs lower layers. Removing a lower layer under a
  live mount is undefined in overlayfs; the sandbox may read a file that
  is half gone. Nothing in ADR-009 records that a layer is mounted:
  `OciImageStore::layers` hands out a list of paths and forgets it.
- **A layer a pull is about to use.** A pull checks the cache layer by
  layer. A trim that runs while layer 2 of 8 downloads could remove
  layer 5, which the pull already found in the cache, or remove a layer
  this pull committed a moment ago before the pull returns it.
- **Leftovers of other owners.** ADR-009 D8 removes a temporary name
  (a staging tree, a staged blob, a probe) only when `/proc` shows its
  owner is gone, in the store's own boot, PID namespace and time
  namespace, through a `/proc` of that PID namespace. Everything else is
  never judged: owners in another PID or time namespace, owners from an
  earlier boot or another host, and owners that could not read their boot
  id. ADR-009 lists this as a known limit and leaves it to #56: such a
  crash leaves a partial layer and a blob behind for good.

ADR-009 D8 already weighed an `flock` on a per-process lock file, which
decides liveness in every namespace, and rejected it for one reason: std's
`File::lock` needs Rust 1.89, and the MSRV was 1.87; the alternative was a
new `unsafe` wrapper in `boneli-sys`. ADR-012 moved the MSRV to 1.89, so
that reason is gone.

This ADR covers the locks and leases (PR 1 of #56). The accounting, the
eviction policy, the trigger, the eviction steps and the default budget
follow in PR 2 and are added here as D4 to D8 before the ADR is accepted.

## Decision

### D1. Owner locks decide liveness in every namespace

- `LayerCache::new` creates `<root>/locks/owners/<token>`, where
  `<token>` is the 106-character owner token of ADR-009 D8, unchanged
  (`<boot>.<pidns>.<timens>.<pid>.<start>`), takes a shared lock on it and
  keeps it for as long as the cache, or a clone of it, lives. It does so
  before it creates any owned name: the case probes, then staging trees,
  staged blobs and documents, which only a store pulls through its cache.
  It then `fsync`s `locks/owners/`, so the lock file's entry is durable
  before any name it covers is created: after a power loss, a leftover
  name always finds its owner's lock file, and the lock decides instead of
  the `/proc` fallback, which judges no earlier boot.
- `OciImageStore::open` takes the owner lock first and then sweeps. A
  sweep groups the owned names of `layers/sha256/` and `blobs/sha256/` by
  owner and decides each owner once, with an exclusive `try_lock` on its
  lock file, which never creates one:
  - `WouldBlock`: the owner is alive, and its names stay.
  - Acquired: the owner is gone. Its names are removed, and the lock file
    is unlinked, still locked, but only once every one of them is gone. If
    a name is left (for example a tree deeper than `PATH_MAX` under this
    root's path), the lock file stays, so the next judge tries again.
  - No lock file: the names come from a build without this ADR, and the
    `/proc` rule of ADR-009 D8 applies unchanged. A live owner of this
    build always has its file, so the fallback only ever judges old
    builds sharing the root.
  - A lock path that is not a regular file, or an error: nothing is
    concluded, and the names stay (fail closed).
- The same pass removes the lock files of owners that left no name, when
  their exclusive lock can be taken. Names in `locks/owners/` that are not
  owner tokens stay.
- What this closes: owners in another PID namespace or time namespace, an
  earlier boot's owners and owners with a random id are now judged, since
  a lock does not survive its process (`SIGKILL` included) or a reboot.
  The ADR-009 D8 known limit "until #56" ends here for owners of this
  build.
- Two stores in one process share the token and so the lock file. Each
  holds its own shared lock through its own open file description, so
  the process stays alive to judges until its last store is dropped.
- Why not keep `/proc` as the primary rule: it cannot judge any of the
  cases above without a second source of truth per namespace, and the
  lock already is one. Why not a lock per name: a staging tree is a
  directory that the unpacker fills over minutes; one lock per owner
  covers every name it creates, costs one descriptor per store, and needs
  no change to the names of ADR-009.

### D2. Layer pins and leases

- `<root>/locks/sha256/<hex>` is the lock file of the layer `<hex>`.
  `LayerCache::pin(diff_id)` takes a shared lock on it (a `LayerPin`).
  Only a holder of the exclusive lock may remove the layer (PR 2).
- A pull pins **every** `diff_id` of the image right after its config is
  resolved, before it checks the cache for any layer and before it
  requests any layer blob. Pinning at the start, and not layer by layer,
  is what keeps a trim from removing layer 5 while layer 2 downloads: the
  issue's goal covers a layer "a pull is about to use".
- `LayerCache::unpack` takes the `LayerPin` instead of a bare `diff_id`,
  so an unpinned commit does not compile; a pin of another cache's root is
  refused.
- The port's `pull` releases the pins when it returns. The new
  `OciImageStore::pull_leased(&ImageRef) -> Result<Lease, ImageError>`
  hands them to a `Lease` instead, with no gap between pull and pin. The
  lease is built from the manifest and config the pull holds in memory,
  not read back from disk.
- `OciImageStore::lease(&RootfsRef)` reads the config, pins every layer
  first and then checks that each is committed. A missing layer is
  `Failed` with a detail that names it and says "pull the image again";
  the pins taken so far are released.
- A `Lease` offers `rootfs()`, `layers()` (bottom first; a `diff_id`
  listed twice keeps its topmost position, as `layers()` did) and
  `config()`. It holds one descriptor per distinct layer. Dropping it
  releases the pins.
- `lease` does not take the store's pull mutex, so a sandbox start never
  waits for an unrelated pull.
- The inherent `OciImageStore::layers(&RootfsRef)` is removed: an unpinned
  list of paths is exactly the hazard the lease closes, and its only
  intended caller, the Sandbox adapter (#8), has not started. `config`
  stays.
- **Rule for #8:** the Sandbox adapter holds a `Lease` from before the
  mount until `destroy` has returned.
- Lock files are opened by std, so they carry `O_CLOEXEC`, and no sandbox
  inherits a lock through an exec.
- **Descriptors.** A lease holds one descriptor per distinct layer:
  node:22 8, postgres:17 14, at most `MAX_LAYERS` = 128. Under systemd's
  default soft `RLIMIT_NOFILE` of 1,024 that is about 46 concurrent
  node+postgres pods (22 descriptors each) or 7 leases of 128-layer
  images (896). Past that, `lease` and `pull_leased` fail as `Failed`,
  release what they took and do not panic. Rejected for now: sharing one
  descriptor per layer across the leases of a store. It saves descriptors
  only for concurrent leases of the same image, and it adds a refcounted
  table to an always-review crate.

### D3. The lock-file protocol

- Lock files are regular files with mode `0o600`, created on first use.
  A missing file is created with `O_CREAT | O_EXCL`, which never follows a
  symlink; an existing path is checked with `lstat` before it is opened,
  and opened read-write, which never blocks, not even on a FIFO swapped
  in.
- After locking, the open file's `dev`/`ino` (`fstat`) must equal
  `lstat(path)`. A mismatch means an exclusive holder unlinked the file in
  the meantime (or something else was put at the path), and the caller
  tries again.
- A path that is not a regular file is an error that names it (a symlink,
  a directory, a FIFO). A symlink is never followed into a lock or a
  removal: fail closed.
- Only an exclusive holder ever unlinks a lock file, and it unlinks it
  while still holding it, so a shared locker that opened the old file
  sees the mismatch once it gets the lock.
- Retries are bounded at 1,024 (`LOCK_ATTEMPTS`), then
  `Error::LockChanged(path)`. A hang bound, not a target: each retry needs
  an exclusive holder to unlink this very file between our open and our
  lock, and exclusive holders only ever `try_lock`, once per pass. 1,024
  is the bound `create_probe` already uses for a name it cannot get
  (`PROBE_ATTEMPTS`); any bound above a handful works, and one that never
  ends would turn a bug into a hang.
- Shared lockers block (`lock_shared`). Exclusive lockers only ever use
  `try_lock` and never wait while they hold a layer lock, so no lock cycle
  can form.
- `flock` locks belong to the open file description, so two stores in one
  process exclude each other the same way two processes do.
- Weak spot: NFS and CIFS emulate `flock` with POSIX byte-range locks,
  which belong to the process and do not behave this way across hosts. A
  root shared across hosts, or kept on a network filesystem, is
  unsupported, the stance ADR-012 takes for `boneli-store-fs`.

## Consequences

- An owner's leftovers are removed at the next `open` on the root, in
  whatever PID or time namespace or boot it ran, as long as it ran a build
  with this ADR. Leftovers of older builds keep the ADR-009 rule.
- The judge itself is now trusted with removal across namespaces: a bug
  in the protocol removes a live tree. Mitigation: one rule ("only an
  exclusive holder removes, and every user holds the shared lock from
  before it creates or looks"), pinned across processes, with the owner in
  another PID namespace, time namespace and boot, and under a foreign
  `/proc` (`host::foreign_proc_judges_no_owner`).
- Every store holds one more descriptor (its owner lock), every pull one
  per distinct layer of its image, every lease one per distinct layer.
- `locks/` is a new directory under the root; `open` creates it `0o700`.
- Breaking for callers of `boneli-oci` (pre-1.0): `OciImageStore::layers`
  is gone (use `lease` or `pull_leased`), `LayerCache::unpack` takes a
  `LayerPin`, and `Error` has a new variant `LockChanged`.
- Writing temporary names into a store's directories outside a store (for
  example `Client::get_blob` aimed at `blobs/sha256/` by hand) is
  unsupported: such names have no owner lock behind them, and the
  `/proc` fallback judges them as before.
- No new crate, no new dependency edge, no `unsafe`: `File::lock_shared`
  and `File::try_lock` are std since Rust 1.89, the MSRV since ADR-012.
- `boneli-oci` stays on the always-review list.

## Alternatives considered

- **A store-wide reader/writer lock.** One sandbox running for a whole day
  would block every eviction on the root for that day, and a
  long-running runner (#33) always has a sandbox running.
- **`/proc` as the primary rule, locks only for layers.** Leaves the
  ADR-009 known limit open: no leftover of another namespace or an earlier
  boot is ever removed, and eviction would have to count bytes it can
  never reclaim.
- **POSIX `fcntl` locks.** They belong to the process, not the open file
  description, so two stores in one process could not exclude each other,
  and closing any descriptor of the file drops every lock the process
  holds on it. std exposes `flock` only, and a `boneli-sys` wrapper would
  add `unsafe` for a worse primitive.
- **Sharing one descriptor per layer across a store's leases** (D2):
  rejected for now, see Descriptors.
- **Keeping `layers()` next to `lease()`.** An unpinned list of paths is
  the hazard; with no caller yet (#8 has not started), removing it costs
  nothing and keeps the hazard from being reintroduced.

## Accept when

PR 2 of #56 adds the eviction (D4 to D8) on top of these locks and its
tests pass: a trim with budget 1 keeps the layers of a running sandbox and
of a pull in flight, and an eviction interrupted at every step leaves no
listed layer incomplete.
