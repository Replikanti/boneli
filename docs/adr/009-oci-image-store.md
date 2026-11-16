# ADR-009: boneli-oci, an OCI image store with a layered rootfs

- Status: proposed
- Date: 2026-11-16

## Context

Issue #7 builds the `ImageStore` adapter, `boneli-oci`. It pulls an image
pinned by digest from a registry and turns it into a root filesystem that
`boneli-sys` mounts for the sandbox (ADR-007, D7). Its input is hostile in
two ways. The registry, or whoever pinned the image, controls every byte
of the archives, and the store unpacks them onto the host as the runner
user, who holds the git token. A path bug here writes outside the store as
that user, so `boneli-oci` is on the always-review list.

The issue is split into three PRs. Part 1 (this ADR as proposed) unpacks
layers and needs no network. Part 2 adds the registry client (D9 to
D12) and part 3 the store, the port contract and the acceptance, which
settles this ADR.

What the numbers below come from (Docker Hub, anonymous, 2026-11-16,
`linux/amd64`):

- `library/node:22`: 8 layers, 408,439,522 B compressed and 1,156,002,816 B
  uncompressed. The largest layer is 597,621,760 B uncompressed. 34,097
  tar entries, at most 13,350 in one layer. The longest path is 128 B, the
  longest name 65 B, the deepest path 13 components. One layer carries PAX
  headers (3 entries). No device nodes, FIFOs, opaque markers or PAX
  xattrs. 16 setuid or setgid entries, 6 hard links, up to 194 absolute
  symlinks per layer.
- `library/postgres:17`: 14 layers, 167,333,338 B compressed and
  478,661,120 B uncompressed, 2 whiteouts, up to 456 absolute symlinks per
  layer.
- Upstream constants, read in their sources: moby overlay2
  `maxDepth = 128`; Go's `archive/tar` `maxSpecialFileSize = 1 << 20` and
  its end-of-archive rules; `ruzstd` 0.8.2
  `MAXIMUM_ALLOWED_WINDOW_SIZE = 100 MiB` and 0.9.1
  `DEFAULT_MAX_WINDOW_SIZE = 128 MiB`; mke2fs's default
  `inode_ratio = 16384`.

## Decision

### D1. One directory per layer, in the overlay format

Each layer is unpacked into its own directory, keyed by its `diff_id`. A
whiteout is a 0:0 character device and an opaque directory carries
`user.overlay.opaque=y`, the format overlayfs reads with `userxattr`, so
`boneli_sys::Root.layers` mounts the directories as they are (ADR-007, D7
built and measured it for this issue). Docker's overlay2 driver also
stacks one directory per layer, so the merged view is the one Docker
shows.

Rejected: flattening every image into one directory. It needs no new
`unsafe` in `boneli-sys`, but it needs merge rules of its own (a directory
over a symlink, opaque directories, a whiteout next to an entry of the same
layer), and no runtime test pins them; with layers, overlayfs applies its
own, tested rules. Flattening would also store a shared base layer once per
image instead of once.

`boneli-sys` gains the primitives an unprivileged process needs for this
format and std cannot write without `libc`: `make_whiteout` (`mknod` of a
0:0 character device, allowed without `CAP_MKNOD` since Linux 5.8),
`make_fifo`, `mark_opaque` (`lsetxattr`) and `user_xattr` (`lgetxattr`,
`user.` names only, values up to `XATTR_SIZE_MAX`, 65,536 B). All are path
based and never follow a final symlink.

### D2. Path rules

- A leading `/` and `.` components are dropped and `//` collapses, so
  `./a`, `/a`, `a//b` and `a/./b` mean `a` and `a/b`. An entry for `.`,
  `./` or `/` is the layer root; it must be a directory and sets the
  root's mode only.
- A `..` component anywhere is refused, and so is NUL in a PAX `path` or
  `linkpath`. The layer is refused, not the entry: a hostile layer gets no
  partial result.
- Before anything is created, every parent is checked component by
  component with `symlink_metadata`. A symlink or a non-directory as a
  parent refuses the layer; a missing parent is created with mode 0o755,
  as Docker does. Nothing is ever followed: files are created with
  `O_EXCL` after the old entry is removed, devices with `mknod`, xattrs
  with `lsetxattr`, hard links with `linkat` without `AT_SYMLINK_FOLLOW`.
  Why this is enough: the store directory is private (`0o700`) and only
  this process writes it while it unpacks, so the tar stream, read
  sequentially, is the only adversary, and every link it planted is seen
  by the walk before the next create.
- The walk does not repeat itself: it starts below the deepest ancestor
  the layer already created or merged, which it keeps as a set of
  directory paths (D7 has the cost). That set is sound only if a path
  names exactly one directory. Every directory of the layer is in the
  set, so a directory that `lstat` finds at a path outside it was reached
  through an alias, or put there from outside: on a case-insensitive or
  normalizing directory `A` resolves to `a`, and a symlink entry `A` then
  removes the directory `a` while `a` stays in the set. Review of part 1
  wrote a file outside the tree that way on a casefold tmpfs. Such a
  directory refuses the layer wherever it is found: as a parent, as the
  target of a removal or a merge, and on a hard link target's path.
  Rejected: dropping every cached entry at and below an affected name,
  because which names alias depends on the filesystem's folding and
  normalization tables, which the unpacker cannot know; the refusal needs
  no such knowledge. The store also refuses an aliasing root outright
  (D8).
- Symlink targets are data for the sandbox and are written as they are,
  absolute ones included.
- Hard link targets are archive paths under the same rules, must already
  exist in this layer, may not cross a symlink, and may not be a
  directory, a whiteout or the entry itself.
- A later entry for the same path wins. A non-directory over a directory
  removes the tree; a directory over a directory merges, with the later
  entry's metadata (moby).
- Name length is the kernel's: a 256 B component is `ENAMETOOLONG`, an
  error, never a panic.

Whiteouts:

- `.wh.<name>` becomes a 0:0 character device `<name>`, whatever the
  entry's type flag; the byte-exact prefix decides, as in Docker, so
  look-alikes (`.WH.`, fullwidth dots, a zero-width space) are regular
  names.
- `.wh..wh..opq` marks its directory opaque. At the layer root it is
  refused, because what overlayfs does with an opaque lower root is not
  pinned by any test.
- `.wh.`, `.wh..` and `.wh...` are refused (they would name nothing, the
  directory itself or its parent), and so is a `.wh.` prefix in a parent
  component.
- aufs metadata at the root (`.wh..wh.plnk` and the like) is skipped with
  everything under it, as moby does.
- A whiteout hides lower layers only, so a real entry of the same layer
  wins in either order (OCI image spec).

### D3. Entry types and metadata

- Regular files, directories, symlinks, hard links and FIFOs are written.
  A 0:0 character device is a whiteout, the file Docker's overlay2 driver
  writes. Any other character or block device is skipped and counted in
  the layer's sidecar: the sandbox mounts its own `/dev`, and unprivileged
  `mknod` refuses them.
- Modes keep `& 0o1777`: setuid and setgid are dropped, sticky stays.
  node:22 has 16 setuid or setgid entries, and a setuid file owned by the
  runner user would let other local users run it as that user. Inside the
  sandbox the single id mapping (ADR-007, D1) makes setuid meaningless
  anyway.
- uid and gid are ignored: every file belongs to the runner, the one
  mapped id.
- Tar xattrs (`SCHILY.xattr.*`) are never applied. `user.overlay.*` from
  an archive would let a layer redirect or hide paths of other layers, and
  `security.*` cannot be written unprivileged.
- mtimes are kept for files and directories, PAX fractions and negative
  times included. Symlinks get the unpack time, because std cannot set it
  without following the link.
- Directories are created `0o700` and get their final mode and time at
  the end, deepest first, so read-only directories can be filled. A file
  gets its mode and time through its open descriptor, so mode 0 does not
  lock the writer out.

### D4. The tar subset

Go's `archive/tar` is the reader of record: Docker and containerd read
layers with it, and most images are written by it. The reader here accepts
what Go accepts in practice and refuses the rest:

- ustar and GNU magic. V7 and other formats are refused (no current
  writer emits them for images).
- The header checksum as the unsigned or the signed sum.
- Numbers in octal or base-256, up to `i64::MAX`; a negative base-256
  number is refused.
- PAX `x` (`path`, `linkpath`, `size`, `mtime`; every other key is
  ignored), PAX `g` (framing checked, contents ignored, as Docker does),
  GNU `L` and `K`. GNU names come first and PAX overrides them, Go's order.
  A PAX or GNU body may be at most 1,048,576 B, Go's `maxSpecialFileSize`.
- Types `0`, NUL and `7` as regular files (NUL with a trailing `/` is a
  directory), `1`-`6`. Header-only types carry no data whatever their size
  field says. Sparse files (`S`, `GNU.sparse.*`) and every other type are
  refused.
- The end of the archive is Go's: EOF at a header boundary, or a zero
  block followed by EOF or a second zero block. A zero block followed by
  anything else is refused. Bytes after the end are hashed into the
  `diff_id` and counted, never extracted.

Where this is stricter than Go, on purpose: a PAX or GNU header with no
entry after it (Go reports a clean end), a PAX record length with a sign,
V7 headers and sparse files. None of the measured images uses them, and
refusing fails closed.

Rejected: the `tar` crate. docs/ARCHITECTURE.md puts tar reading on the
list of parts we write ourselves, the crate pulls `filetime` and `xattr`
(with `libc` edges), and its unpacker applies its own path and permission
policy that we would have to audit and override.

### D5. Decompression

- gzip: our RFC 1952 framing over `miniz_oxide` 0.9.1's raw deflate
  (`default-features = false`, `with-alloc` for the streaming state).
  Reserved `FLG` bits and `CM != 8` are refused, `FEXTRA`, `FNAME`,
  `FCOMMENT` and `FHCRC` are skipped, `ISIZE` is checked. Several members
  decode as one stream, and any byte after the last member that does not
  start another member is refused, as in Go. CRC-32 is not computed,
  because the `diff_id` covers every decoded byte; a corrupted CRC field
  alone therefore passes, and the blob digest (part 2) covers it on the
  compressed side. `miniz_oxide` forbids `unsafe` in its own code. It
  pulls `adler2` (Adler-32 for the zlib format, `forbid(unsafe_code)`),
  which we do not use, but the edge is unconditional; this ADR approves
  the crate name.
- zstd: `ruzstd` 0.9.1's `FrameDecoder` (`default-features = false`,
  `std`, which pulls no crate): frames in sequence, skippable frames
  skipped, anything after the last frame refused, checksums read but not
  verified (no `hash` feature, which would pull `twox-hash`; the
  `diff_id` covers the bytes). The reserved bit of the frame header
  descriptor must be 0 (RFC 8878 says a decoder must check it; ruzstd does
  not), so the reader checks it before ruzstd reads the header.
- At least 0.9.1, and with it MSRV 1.87 (decided by the operator during
  part 1, 2026-11-16). `cargo deny check` refused 0.8.2 for
  RUSTSEC-2026-0344: a crafted frame under 128 KB makes one block expand
  to gigabytes, because 0.8.2 never bounds a block's decoded size, so the
  counting reader of D7, which sees the output only after a block is
  decoded, cannot stop it. The fix exists only in 0.9.1, which declares
  `rust-version = 1.87`; resolver 3 picks versions by `rust-version`, so
  the workspace's `rust-version` moves from 1.85 to 1.87. The cost is
  only the declared floor: CI and the hosts build with current stable.
  Rejected: an advisory ignore in `deny.toml` (a denial of service on
  hostile input, and widening the deny policy needs an ADR of its own),
  and refusing zstd layers until later (zstd is in the OCI layer media
  types the store must read). ADR-005 records "the workspace MSRV of 1.85
  stays" for the TLS stack; that still holds for those crates (none
  declares more than 1.85), but the workspace floor is now 1.87. ADR-005
  is accepted and keeps its text; this paragraph is the record.
- The zstd window cap is 100 MiB, set with `set_max_window_size`. ruzstd
  0.9.1 checks it when a frame header is read, for the first frame,
  later frames and single-segment frames (whose window is their content
  size) alike, before it allocates the window (read in its source;
  0.8.2 checked only later frames, which part 1 first worked around with
  its own header parse). The decoder's memory is the window plus one
  block of at most 128 KiB, which 0.9.1 now enforces. Why 100 MiB: it is
  the value ruzstd 0.8.2 hard-coded and the plan adopted; 0.9.1's default
  and zstd's own default limit (`ZSTD_WINDOWLOG_LIMIT_DEFAULT = 27`) are
  128 MiB. Consequence: a layer compressed with `zstd --long`, whose
  default window log is 27 (128 MiB), is refused; raising the cap to
  128 MiB admits it at 28 MiB more memory per decoding pull. Part 3
  measures the first-stack images and settles the value.
- `ruzstd` contains `unsafe` in its ring buffer, and RUSTSEC-2024-0400 was
  an out-of-bounds read there (patched in 0.7.3). `cargo deny check` runs
  advisories in CI. Its input is digest-verified before it is decoded
  (part 2), so the adversary is whoever pinned the image, not the network.
  ruzstd also does not read some fields: one flipped byte of the test
  fixture's sequences section (measured with 0.8.2 and again with 0.9.1)
  decodes to the same output, which the `diff_id` then matches, so the
  result is the right bytes.
- Every decompressor's output passes a counting reader that refuses the
  first byte over a limit (D7), so a bomb stops there.

Rejected: `flate2` (pulls `crc32fast` and `cfg-if` for a CRC we do not
need, plus a backend switch), the `zstd` crate (C bindings with a build
script, against "pure Rust" in docs/ARCHITECTURE.md).

### D6. SHA-256: ring's, exported by boneli-https

The one SHA-256 of the repository is `boneli_https::Sha256`: ring's
SHA-256 through rustls' public hash-provider API
(`rustls::crypto::hash`, the `hash_provider` of
`TLS13_AES_128_GCM_SHA256`, read through an exhaustive `match` on
`SupportedCipherSuite` with no panic path). This widens ring's exception
in docs/ARCHITECTURE.md and ADR-005 from "TLS only" to "TLS and content
hashing", still confined to `boneli-https`. Reasons:

- The same BoringSSL-derived code is already linked into the runner and
  already hashes the transcript of every TLS 1.3 connection on a SHA-256
  suite, so no foreign code is added and no crate or edge either.
- It uses the CPU's SHA instructions: ring 0.17.14 dispatches to
  `sha256_block_data_order_hw` on x86_64 with the SHA extensions and on
  aarch64, with AVX and SSSE3 paths on older x86_64.
- ring is audited and widely deployed.

Weak spot: dropping ring later means replacing the hash too. The single
type confines that to one file and its tests. A rustls update that changes
the API fails to compile there; one that swaps the provider fails the
known-answer tests and `hash_provider_is_sha256`.

ADR-004 requires the file store (#4) to use "a cryptographic digest from
a vetted crate" and names `sha2` as the planned crate. The rule still
holds and only the crate changes; ADR-004 stays as it is, because an
accepted ADR changes only its status line. `sha2` leaves the dependency
table and `tools/architecture.toml`, so #4 uses the same type.

Alternatives:

- Our own FIPS 180-4 implementation: rejected, it duplicates code that is
  already linked.
- `sha2` 0.11: rejected, it adds 6 crate names and the strict edge
  `cpufeatures -> libc` on aarch64 for a second SHA-256 next to ring's.
- Our own TLS primitives, or a pure-Rust rustls provider such as
  `rustls-rustcrypto` that would make the hash pure Rust along with the
  rest: rejected. TLS primitives handle secret keys, need constant-time
  code and fail open on a signature-verification bug, whereas a
  deterministic bug in a hash fails closed. ADR-005 is not edited.

### D7. Limits

`Limits::new(max_layer_bytes, max_image_bytes, max_image_entries,
max_special_bytes, max_depth)` has no defaults and refuses a zero (the house style of
ADR-003 and ADR-008), so the values live in one place, the store (part 3).
Every limit is inclusive: the limit passes, one more is refused. The values
the store will use, and why:

- Per layer: 4,294,967,296 B uncompressed (4 GiB), 7.2 times node:22's
  largest layer of 597,621,760 B. Counted on the decoded stream while it
  is read, trailing bytes included. Lower refuses real first-stack images
  sooner; higher lets one layer fill more disk before it is refused. Known
  casualty: images with layers above 4 GiB (CUDA and ML images) are
  refused until the value is raised.
- Per image: 17,179,869,184 B (16 GiB), 14.9 times node:22's
  1,156,002,816 B, and 1,048,576 entries, 30.8 times node:22's 34,097.
  16 GiB divided by mke2fs's default 16,384 B per inode is exactly
  1,048,576, so the two caps exhaust the same default ext4 at the same
  time; neither is the weaker bound. Because the entry cap stands for
  inodes, the directories the unpacker creates for missing parents count
  as entries too; otherwise one tar entry at depth 128 would create 127
  inodes the cap never sees. Layers already in the cache are charged from
  their sidecars, so a warm cache and a cold one reach the same verdict;
  a layer is charged only once it is committed, never on a failed
  attempt.
- A PAX or GNU extension body: 1,048,576 B, Go's `maxSpecialFileSize`, so
  every archive Go reads passes; it is read into memory, so this is the
  memory one header may take.
- The zstd window: 100 MiB (D5).
- Path depth: 128 components after normalization, whatever the entry's
  type. Why a cap at all: review of part 1 measured a layer of ~1,900-deep
  entries that cost 407 ms of CPU per entry, under every byte and entry
  cap. The quadratic part of that is gone (the parent walk starts below
  the deepest directory this layer already verified, so an entry in a
  known directory costs no `lstat` for its parents), but the kernel still
  resolves every path component by component, so each entry stays linear
  in its depth. Measured after that change (release build, btrfs on the
  dev host, 300 entries per depth, two runs): per entry 0.034-0.061 ms at
  depth 13, 0.061 at 64, 0.068-0.110 at 128, 0.13-0.23 at 192-256, 0.46 at
  384, 0.48-0.65 at 512, 0.96 at 1,024 and 4.2 at 1,900; a directory
  created for a missing parent costs 0.037-0.068 ms at depth 13 to 128 and
  0.11-0.15 ms at 512. 128 is the deepest measured depth whose per-entry
  cost stays in the shallow band (within 2 times depth 13), so the worst
  layer within the entry cap costs about as much as the worst shallow
  one: 1,048,576 entries at 0.11 ms is about 2 minutes, against about
  11 minutes at depth 512 (0.65 ms). It is 9.8 times node:22's deepest path of 13
  components. Two more bounds hold with room: a traversal that holds one
  descriptor per level (std's `remove_dir_all`) needs at most 129
  descriptors, far below systemd's
  default soft `RLIMIT_NOFILE` of 1,024 next to the up to 163 layer
  descriptors a root mount opens (ADR-007, D7); and an entry at the cap
  has an in-sandbox path of at least 256 B, so its components may average
  31 B before it exceeds `PATH_MAX` (4,096 B). A lower cap refuses deeper
  real trees sooner; a higher one buys deeper trees with per-entry CPU
  that grows past the shallow band (0.46 ms at 384, about 4 times the
  cap's).

### D8. The cache layout and concurrency

- `<root>/layers/sha256/<hex>` is the layer directory and
  `<root>/layers/sha256/<hex>.stats` its sidecar: uncompressed bytes,
  entry count and skipped devices, as
  `bytes N\nentries N\nskipped-devices N\n`, parsed exactly.
- A layer is unpacked into `layers/sha256/.tmp-<pid>.<starttime>.<n>/`
  (the start time from `/proc/self/stat`, so a reused pid is told from a
  live owner when the store cleans up). Lookups use hex names only, so a
  dot name is never mistaken for a layer. Its sidecar is staged next to
  it as `.tmp-<pid>.<starttime>.<n>.stats`, so every temporary tree of
  every process has its own (part 1 first derived it with
  `with_extension`, which drops the counter; review measured two caches
  in one process committing each other's sidecars). The tree is staged in
  the directory it is committed into because a rename within one
  directory does not rewrite the moved directory's `..`, so a read-only
  layer root (mode 0o555) needs no write permission lent to it, and no
  crash can leave a committed root with a mode it did not have. Part 1
  first staged under `<root>/tmp/` and lent `u+w` for the rename.
- `LayerCache::new` refuses a `layers/sha256/` where names alias each
  other. It creates a probe file and looks up its upper-case form and,
  for a second probe with a precomposed `é`, its decomposed form; if
  either lookup finds the file, the directory is case-insensitive or
  normalizing (ext4 or f2fs casefold, tmpfs `casefold`, ZFS
  `normalization`, vfat), and the store fails closed. A probe is named
  `.probe-…-<pid>.<starttime>.<n>`; a name that exists is skipped and
  never removed, because it may be a crashed process's leftover with the
  same pid (deterministic in a container) or the live probe of a runner
  in another PID namespace sharing the store, and only its owner may
  delete it. A probe rather
  than the casefold inode flag, because it also catches filesystems that
  alias without that flag. Why checking that one directory suffices:
  casefold is a directory flag that only an empty directory can take and
  that new subdirectories inherit, normalization is a property of the
  whole filesystem, and the unpacker never sets inode flags (it has no
  ioctl, only std calls and the `boneli-sys` primitives of D1), so every
  directory below a case-sensitive `layers/sha256/` is case-sensitive
  too. The alias refusal of D2 holds on its own when a tree is unpacked
  anywhere else.
- The commit, in this order: the `diff_id` matches; the staged sidecar is
  written; one `syncfs` on the store's filesystem, through a descriptor
  of the temporary tree opened before anything was written into it,
  makes the layer's file
  data, its directory entries, its final modes and the staged sidecar
  durable; the sidecar is renamed into `layers/sha256/` and that
  directory is `fsync`ed; the layer directory is renamed to
  `layers/sha256/<hex>`, the commit point, and `layers/sha256/` is
  `fsync`ed again. A committed layer therefore always has its sidecar and
  its data on disk; a crash before the last `fsync` loses at most the
  rename, and the layer is unpacked again. Why `syncfs` and not an
  `fsync` per file: measured on a synthetic layer the size of node:22's
  largest (13,350 files in 100 directories, 608,385,024 B of tar; release
  build, btrfs on LUKS on the dev host's NVMe, two rounds), an `fsync` of
  each of the 13,451 inodes after the unpack took 18.4 s and 17.0 s,
  one `syncfs` 0.35 s and 0.32 s, against 1.7-3.9 s for the unpack
  itself. The cost of `syncfs`: it also writes back other dirty data on
  the same filesystem, which on a runner host is the runner's own; since
  Linux 5.8 it reports writeback errors, and the runtime needs 5.19
  (ADR-007, D3). It reports them relative to the error state sampled
  when its descriptor was opened, and an error another caller has
  already seen counts as old for a descriptor opened later; the
  descriptor is therefore opened when the temporary tree is created, so
  an error during the layer's own writeback is reported to its commit.
  `boneli_sys::sync_filesystem` wraps the call.
- A mismatch or an error removes the temporary tree and its staged
  sidecar, and the budget is left as it was. The removal holds at most
  one directory descriptor at a time, whatever the depth: it walks by
  path, lists each directory exactly once while it removes the
  non-directories, keeps the names of the subdirectories (at most the
  tree's entry count) and closes the listing before it goes down a
  level, and it gives each directory `u+rwx` first, because final modes
  may be 0. std's `remove_dir_all` holds one descriptor per level and
  left a deep tree behind under `ulimit -n 1024` in review; a first
  bounded version listed a directory again after each subdirectory and
  took 28.6 s for 80,000 sibling directories (release build, btrfs on the
  dev host), now 2.6 s against 2.2 s for `remove_dir_all` and 2.7 s for
  the unpack itself. It unlinks by path rather than relative to the
  directory's descriptor, because std has no `unlinkat` and the path
  walk costs only that 20 percent over `remove_dir_all`; a `boneli-sys`
  wrapper would add `unsafe` for it. With the unpacker's own handful of
  descriptors (the blob, one open file, one directory, the `syncfs`
  descriptor), a cleanup fits any descriptor limit a runner can start
  under; the test runs it under 48.
- Two stores committing the same layer: the rename of the second fails
  because the directory exists; it discards its tree and reads the
  winner's sidecar. The same `diff_id` means the same bytes, so the trees
  and their totals are equal, and the loser's budget is charged with them.

### D9. The registry protocol and the anonymous token flow

Part 2 adds the registry client. It speaks the read side of the OCI
distribution API, `GET /v2/<repository>/manifests/<digest>` and
`GET /v2/<repository>/blobs/<digest>`, over `boneli-http` (ADR-003) and
`boneli-https` (ADR-005), and nothing else: no tags, no listing, no push.

- **References.** An `ImageRef` is parsed before any request. The name's
  first component is a registry host when the name has more than one
  component and the first contains `.` or `:` or is `localhost`, the rule
  of `distribution/reference`; without one the store's default registry
  applies. The repository path is `/`-separated components
  `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`, at most 255 B
  (`RepositoryNameTotalLengthMax`, applied to the path after the host).
  Nothing is normalized: `node` is not rewritten to `library/node`,
  uppercase is not lowered, whitespace is not trimmed, so a look-alike
  (Cyrillic `о`, U+200B, U+00A0) is refused, never resolved to a real
  repository. The digest is `sha256:` and 64 lowercase hex digits only;
  `sha512` is refused, because nothing in the first stack uses it and the
  repository has one hash (D6). The platform is `os/arch[/variant]`, each
  part `[a-z0-9]+`. Every rejection is `Failed` (D11) and makes no
  request.
- **Documents.** The `Accept` field lists the OCI index, the OCI manifest,
  Docker's manifest list and Docker's manifest v2. A document is read
  into memory up to the document limit (D12), or exactly its descriptor's
  size when an index gave one, and its SHA-256 must equal the requested
  digest before it is parsed; `Docker-Content-Digest` is not read, the
  bytes are. The kind comes from the `mediaType` field, or from
  `Content-Type` (parameters dropped, lowercase) when the field is absent;
  both present and different refuses the document, so a server cannot
  make one body parse as two kinds. `schemaVersion` must be 2. Refused
  outright: schema 1, a document with both `manifests` and `layers`, a
  nested index (an index entry that names an index, or an entry that
  names a manifest and serves an index), an entry whose media type differs
  from the document it serves, unknown media types (a Cyrillic letter
  inside a known one is unknown), config media types other than OCI's and
  Docker's, foreign and nondistributable layers, any layer with `urls`
  (the client fetches only from the registry), and `size` values that are
  not unsigned 64-bit integers (negative, fractional, an exponent, above
  `u64`, a string). Duplicate JSON keys are refused by `boneli-json`.
  Accepted layer types: `application/vnd.oci.image.layer.v1.tar`, `+gzip`
  and `+zstd`, and `application/vnd.docker.image.rootfs.diff.tar.gzip`.
- **Platforms.** An index entry matches when its os and architecture are
  the requested ones exactly and its variant is the requested variant; a
  missing variant matches only a missing variant, except on `arm64`, where
  a missing variant and `v8` are the same (the OCI image spec lists `v8`
  as the only arm64 variant, and indexes write it either way). An entry
  with an `unknown` os or architecture, which Docker's attestation
  manifests carry, never matches. No match is `NotFound`; more than one
  is `Failed`, because the store would otherwise pick by position. The
  config's platform must match the request too: for a manifest named
  directly a mismatch is `NotFound` (the image is not for this platform,
  the contract's `platform-pinned`), for one selected from an index it is
  `Failed` (the index contradicts the image). The config must list one
  `diff_id` per layer.
- **Blobs.** A blob is streamed into a temporary file next to its
  destination, named like a layer's temporary tree
  (`.tmp-<pid>.<starttime>.<n>`, D8), and hashed on the way. It must be
  exactly its descriptor's size: the client reads that many bytes and then
  one more, so a longer body is refused whatever its framing, and an end
  before it is refused too. Only a matching digest is `fsync`ed and
  renamed to the destination, whose directory is then `fsync`ed; on any
  error the temporary file is removed, so a tampered blob never reaches
  `blobs/`. A blob's descriptor size is checked against the blob limit
  (D12) when its manifest is read and again before the request.
- **Tokens.** Every first request to a registry gets a `401` with a
  `WWW-Authenticate` challenge (Docker Hub, measured). It is parsed as RFC
  9110, section 11.6.1, defines it: several challenges per field, quoted
  strings with escapes, token68. Exactly one `Bearer` challenge must be
  there, with a `realm` that is an `https` URL on one of the registry's
  token hosts (D10); `Basic` alone is refused. The token request is `GET
  <realm>` with `service` and `scope` appended to the realm's query (`&`
  when it has one), percent-encoded; a missing `scope` becomes
  `repository:<repository>:pull`. It carries no credentials (#55 adds
  them). The token is `token`, or else `access_token`; it must be a
  non-empty string of visible ASCII, so it can neither be blank nor break
  or extend the `Authorization` field it goes into. It is reused for the
  whole pull and fetched again once per fetch on a `401`. `expires_in`
  (300 s on Docker Hub) is not read: a token that expired mid-pull gets
  exactly one `401` and one new token, with no clock in the client.
- **Connections.** One connection per request, no reuse: a node:22 pull is
  about 22 requests (the first `401`, the token, the index, the manifest,
  and the config and 8 layers with one redirect each). Reuse would save handshakes but
  needs the idle check of ADR-003, item 12 across hops that change hosts;
  part 3's acceptance logs the pull time, which shows whether the
  handshakes matter (not measured yet).

Rejected: following tags (a tag is mutable, and the port pins digests,
ADR-004), trusting `Docker-Content-Digest` (the header is the registry's
claim, the hash is ours), and reading `expires_in` (it needs a clock in
the client and saves at most one request per expiry).

### D10. Hosts, redirects, and why pulls bypass boneli-egress

- **The allowlist.** A `Registry` names its image-name host (`docker.io`),
  its API host and port (`registry-1.docker.io:443`), its token hosts
  (`auth.docker.io`) and its redirect suffixes (`.docker.com`), every host
  in the grammar of ADR-003 (`boneli_http::Target::parse_authority`: no
  userinfo, LDH labels, no numeric forms like `127.1`, lowercase).
  `Registry::docker_hub()` holds the measured values. An image name's host
  selects a registry when it equals the name without a port, or the API
  host with no port or the API port, after ASCII lowercasing; anything
  else is refused before a request: a trailing dot, a longer or shorter
  host, an `xn--` look-alike, userinfo, another port, an IP literal. A
  token realm must be `https` on a token host and port exactly.
- **Redirects.** Only blob requests follow redirects (`301`, `302`, `303`,
  `307`, `308` with exactly one `Location`), at most 10, Go `net/http`'s
  limit; Docker Hub uses one (measured), so 10 leaves room for CDN chains
  and still ends a loop after 11 requests. A relative `Location` resolves
  against the request URL (RFC 3986, section 5.2). The target must be
  `https` and the API host and port exactly, or a host strictly under a
  redirect suffix, on a dot boundary, on port 443:
  `production.cloudfront.docker.com` passes, `evildocker.com`,
  `docker.com` and `docker.com.evil.example` do not. Manifest and token
  requests do not follow redirects; a `3xx` there is `Failed`.
- **Authorization** goes only to the API host and port. Token and
  redirect hosts never see it, so a CDN log or a hostile redirect target
  gets no token.
- **Why pulls bypass `boneli-egress`.** The egress proxy (ADR-006) is the
  sandbox's broker: #32 builds its allowlist per sandbox phase, and its
  connection log is the sandbox's evidence, so runner traffic there would
  mix the two. A pull runs in the runner, the trusted side that already
  reaches the forge directly, and its integrity does not depend on the
  network path, because every byte is checked against the pinned digest.
  An image reference may come from an agent later (ARCHITECTURE plan step
  3); the request forgery that would allow is closed here: `https` only
  with verified certificates, every host from the allowlist above, and
  the token to the API host only. Weak spot: a customer network that
  forces an HTTP proxy cannot pull yet; `boneli_http::connect_tunnel` plus
  `boneli_https::connect_over` make that an additive `Dial` (#55).
- **The `Dial` seam.** Requests go through a crate-local trait, modeled on
  `boneli-egress`'s `Upstream` (ADR-006, D11): no use case drives it, so
  it is not a `boneli-app` port and needs no in-memory adapter. The tests
  serve a fake registry over `UnixStream::pair`, so the client's framing
  is the real code. The production `TlsDial` connects TCP to each address
  in turn and completes the handshake with `boneli_https::connect_over`,
  certificates always verified (ADR-005), with the caller's
  `ConnectOptions`. It uses `connect_over` rather than
  `boneli_https::connect` so that the request's deadline (D12) sits on the
  socket below TLS: a TLS read returns only once a whole record has
  arrived, so a peer that sends a record a byte at a time, each byte
  within the read timeout, would hold a read above TLS open far past any
  deadline set there. `connect_over` checks the server name only once
  TCP is connected, so `TlsDial` first checks the host and port against
  the ADR-003 grammar (`Target::parse_authority`, the host in its
  canonical lowercase form) and refuses anything else before it resolves
  a name or opens a connection, as `connect` does (ADR-003, item 3).
  Without it `127.1`, `2130706433` or `0x7f000001` reached a loopback
  listener through `getaddrinfo`. The client's hosts have passed that
  grammar and the allowlist already; the check keeps `TlsDial` safe for
  any caller. The tests run `TlsDial` against a local rustls server with
  boneli-https's test certificates, which takes the dev-dependency edge
  `boneli-oci -> rustls`; production TLS stays in boneli-https.

### D11. Error classification

The `ImageStore` port has two errors (ADR-004): `NotFound` and `Failed`
with a detail that is never blank (ADR-004, D4). The client returns a
`PullError` with the same two cases:

- `NotFound`: a `404` on the manifest the reference names; a `401` on a
  manifest with a token
  fetched for that very request, before the API host answered any request
  of the pull with a document, a blob or a redirect to one, which is
  Docker Hub's answer for an unknown repository (measured:
  `401 UNAUTHORIZED` even with a fresh token); no index entry for the
  platform; a manifest named directly whose config is for another
  platform. Once the API host has answered, the repository exists, so a
  later `401` is `Failed`; that holds when part 3 fetches a blob first
  because it read the manifests from its cache.
- `Failed`, everything else: an invalid reference or a refused registry
  host; a `404` on a blob or on a manifest an index named (the manifest
  or index named it, so the registry is broken, not the image missing,
  and a store that remembered "no such image" would turn a half-replicated
  mirror into a permanent miss); a second `401` on a blob, or on a
  manifest after the pull was authorized; `429`; `5xx`; any other status;
  a refused redirect, realm or token; a network, TLS or HTTP error; a
  deadline; a document outside D9's subset; a config that contradicts its
  index entry; a digest or length mismatch.

The detail names hosts, digests, sizes and statuses. It never carries the
token or a response body: a body is the registry's text and may be
large or hostile, and the token is a credential. There are no retries
beyond the single re-authentication of D9: a retry policy belongs to the
store (part 3), which knows whether a pull is worth repeating.

### D12. Limits and deadlines

`FetchLimits::new(document, max_token_bytes, max_head_bytes, max_headers,
max_layers, max_blob_bytes, max_pull_bytes)` and `Timeouts::new(io, setup, min_rate)`
have no defaults and refuse a zero (the house style of ADR-003, ADR-008
and D7), so the values live in one place, the store (part 3). Every limit
is inclusive. The values the store will use, and why (measured on Docker
Hub, 2026-11-16):

- **Documents** (index, manifest, config), as `boneli_json::Limits`:
  4,194,304 B, depth 16 and 65,536 values.
  - 4 MiB is the size the OCI distribution spec tells clients to expect
    for a manifest push ("at least 4 megabytes"), so a registry that
    follows the spec cannot hold a manifest this client refuses for
    size; the largest measured document is 10,237 B (the postgres index),
    409 times less. Lower would refuse spec-conforming documents; higher
    only buys memory for documents no registry should hold.
  - Depth 16 is 4 times the measured maximum of 4 (annotations objects
    nest one more); lower risks refusing a manifest with nested
    annotations, higher only admits nesting no real document has
    (`boneli-json` caps every consumer at 512 anyway, ADR-008, D6).
  - 65,536 values is 294 times the measured 223; an index entry with a
    platform is about 10 values, so 65,536 holds thousands of entries.
    Lower would refuse large multi-platform indexes; higher costs 136 B
    per value (ADR-008, D5).
  - The peak memory per document is then about 2 × 4 MiB (the body and
    its strings) + 136 B × 65,536 = 17,301,504 B, about 16.5 MiB
    (ADR-008, D5), and a pull holds at most two at a time (an index and a
    manifest).
- **The token response**: 65,536 B, 11.9 times about 5.5 KB, the measured
  response, which carries the 2,696 B token twice (`token` and
  `access_token`). Lower would refuse registries with larger JWTs (more
  claims); higher costs only memory, read once per token. Its depth and
  value limits are the document's.
- **Response heads**: 16,384 B and 64 fields, 20 times and 4 times the
  measured 815 B and 16 fields (CDN responses carry the most). Lower
  would refuse a CDN that adds tracing fields; higher lets a server make
  the client buffer more per request. Bodies are not held to a framing
  limit; the client checks them against what it expects (a document
  limit, a token limit, a descriptor size).
- **Layers**: 128 per manifest, moby overlay2's `maxDepth`, so every image
  Docker can run passes. ADR-007 caps the root overlay at 163 lower
  layers, since `25 * 163 + 19 = 4094 <= 4096` and `25 * 164 + 19 =
  4119`, which leaves 35 for #8's own layers. Higher would admit images
  Docker refuses and eat that headroom; lower would refuse images Docker
  runs.
- **Blobs**: a descriptor size of at most 4,294,967,296 B, the per-layer
  cap of D7, checked when the manifest is read and before the request,
  because a blob is downloaded in full before it is unpacked, so this is
  the disk one download may take. A plain tar layer is its blob, so a
  layer at D7's cap still downloads. Compression of incompressible data
  adds a few bytes per block (gzip stored blocks: 5 B per 65,535 B, about
  0.008 percent), so a compressed layer of incompressible data a few
  hundred KB under the cap can be refused here; none of the first stack is
  near it. Higher would let one download fill more disk than a layer may
  have; lower would refuse layers D7 admits.
- **The pull**: the descriptor sizes of a manifest's config and layers,
  summed with checked arithmetic (a sum beyond `u64` is over the cap), at
  most 17,196,646,400 B, which is 16 GiB plus 16 MiB. Checked when the
  manifest is read, before the config or any layer is requested, and
  from descriptor sizes only, so a warm cache and a cold one reach the
  same verdict (as in D7); each blob must be exactly its descriptor's
  size, so the sum is what the pull downloads. Why a cap of its own: D7
  charges decoded bytes, and compressed-side padding decodes to almost
  nothing (gzip `FNAME` and `FCOMMENT` are skipped without a length
  bound, zstd skippable frames are skipped), so without it 128 layers of
  4 GiB pass every other limit and download 512 GiB, 32 times D7's
  per-image budget. The index and the manifest are outside the sum; each
  is at most the document limit.
  - Derivation: an honest image at D7's per-image budget, 17,179,869,184
    decoded bytes, downloads the most when its layers are incompressible,
    because then each compressed layer is its decoded bytes plus framing.
    Measured on 2026-11-16 over 67,108,864 B of random bytes, bytes over
    the input: pigz -1/-6/-9 22,855/22,859/20,498; Python's zlib (gzip
    levels 1/6/9) 20,503/20,503/20,423; Go 1.26 `compress/gzip` 20,503
    at the default and best levels and 5,148 at best speed and Huffman-only; GNU gzip
    -1/-6/-9 11,280/10,258/10,258; zstd -3 and -19 1,550. The zlib and
    Go figures are 5 B per 16 KiB of input, one stored block header each.
    The worst, pigz -6, is 0.0341 percent. Over the budget that is 256 ×
    22,859 = 5,851,904 B. Each of up to 128 layers adds its fixed framing
    once (gzip header and trailer, 18 B, or a zstd frame header and
    checksum, at most 22 B, plus a partial last block and an optional
    file name), bounded generously by 1 KiB per layer, 131,072 B. The
    config is at most the document limit, 4,194,304 B. The honest worst
    case is then 17,179,869,184 + 5,851,904 + 131,072 + 4,194,304 =
    17,190,046,464 B. The cap rounds the overhead up to 1/1024 of the
    budget, 16,777,216 B, 1.65 times the 10,177,280 B needed, so an
    encoder whose stored blocks are as small as about 6.9 KB (5 B each,
    after the config and framing allowances) still passes.
  - Lower, down to the 16 GiB budget itself, refuses an image of
    incompressible gzip layers that D7 admits, by up to about 10 MB;
    higher admits nothing honest and lets a hostile image download more
    padding that decodes to nothing. At this cap a pull downloads at most
    what an honest image at D7's budget downloads.
- **Deadlines**: a fetch of `size` bytes must complete by `setup + size /
  min_rate`; for a document without a descriptor, `size` is the document
  limit. One deadline covers the fetch with its token request
  and its redirects, so a server cannot extend it by answering `401` or
  redirecting. Each read and write also has `io` as its timeout, and every
  read and write after the deadline fails at once, so a body that stalls
  fails within `io`, and one that trickles under `io` fails at the
  deadline, within one `io` of it (`slow_body_deadline`). `TlsDial` holds
  the deadline below TLS (D10). The TCP connect takes at most
  `connect_timeout` or what is left of the deadline. Weak spot: name
  resolution uses `getaddrinfo`, which has no timeout. The values are
  part 3's, measured with the acceptance pulls; the plan's starting point
  is `io` 30 s, `setup` 30 s and `min_rate` 1 MiB/s, which gives node:22's
  largest compressed layer, 211,826,577 B, 30 + 202 = 232 s.

## Consequences

- The sandbox mounts registry images without root and without a
  flattening step, with overlayfs's merge rules.
- The runner gains one more C-backed path, ring's SHA-256, inside the
  crate that already holds ring.
- `boneli-sys` grows by four path-based primitives and a `syncfs`
  wrapper; `unsafe` stays there.
- Every commit costs one `syncfs`, which also writes back other dirty
  data on the store's filesystem (D8).
- Images that need devices, setuid bits, xattrs, sparse files, V7 tar,
  layers above 4 GiB or paths deeper than 128 components do not pull. None of the first-stack images does.
- `boneli-oci` is on the always-review list (#7 STOP 1).
- Pulls reach registries directly from the runner, not through
  `boneli-egress`, limited to each registry's allowlisted hosts (D10).
- Images that need a tag, a nested index, schema 1, a `sha512` digest,
  foreign or nondistributable layers, more than 128 layers, a download of
  more than 16 GiB plus 16 MiB or a registry login do not pull (#55 adds
  credentials).

## Alternatives considered

Flattening (D1), the `tar` crate (D4), `flate2` and the `zstd` crate (D5),
`sha2`, our own SHA-256 and a pure-Rust TLS provider (D6), tags,
`Docker-Content-Digest` and `expires_in` (D9), pulls through
`boneli-egress` and `boneli_https::connect` (D10), each with the reason
it lost in its decision.

## Accept when

Part 3 of #7 pulls `node:22` and `postgres:17` on x86_64 and arm64 and runs
both in the sandbox.
