# ADR-007: The sandbox runtime: single id mapping, seccomp policy, kernel floor and spawn model

- Status: proposed
- Date: 2026-11-13
- Accept when: PR 4 of #6 merges with every host test green in CI on both
  architectures and in a dev-host run.

## Context

`docs/ARCHITECTURE.md` ("Isolation") builds the sandbox runtime in Rust
directly on syscalls instead of Docker or Podman: user, mount, PID,
network, IPC, UTS and cgroup namespaces, `pivot_root`, cgroups v2, a
seccomp-bpf filter assembled in Rust, `no_new_privs`, no capabilities and
Landlock. Issue #6 builds that runtime as the support crate `boneli-sys`,
the only crate where `unsafe` is allowed (ADR-001). A bug in it is a
security bug: the workload in the sandbox is code from a customer's
repository and from an agent, and the runtime is all that stands between
it and the host user's files, the network and the other sandboxes.

The issue leaves four decisions open, made here: how ids are mapped, which
syscalls the filter denies, which kernel the runtime requires, and how a
sandboxed process is started. It also fixes how the runtime is tested,
because none of it can be tested without a host that allows unprivileged
user namespaces, and how the lints of the unsafe crate are kept honest.

The work lands in four PRs under #6. This ADR is written in the first one
and grows while it is proposed: PR 2 adds the namespaces, mounts and broker
sockets (D7), PR 3 the cgroups (D8), PR 4 the privilege drop (D9),
Landlock (D10) and, in D2, the census of every syscall, the comparison
with Docker's default profile and the residual risk. PR 4 sets it to
accepted.

Measurements quoted below were taken on 2026-11-13 on the dev host
(Fedora 44, Linux 7.2.10 x86_64, uapi headers 7.2.4, cargo 1.98.0, libc
0.2.191) unless they name CI.

## Decision

### D1. Single id mapping

Every sandbox has one user namespace with exactly one line in each map:
`<inside> <host> 1`.

- **host** is the caller's effective uid (and gid). It is the only
  mapping an unprivileged process may write for itself; ranges of
  subordinate ids need the setuid helpers `newuidmap`/`newgidmap`, which
  ARCHITECTURE excludes (a setuid helper is host attack surface the runner
  does not need).
- **inside** is the caller's choice (`Ids::new`): 0 (root) for images that
  need it, or the image's user. Root inside is not always right:
  PostgreSQL refuses to run with euid 0 (`check_root` in its server
  startup), and #31 runs PostgreSQL in the pod, so #8 passes the image's
  user or 0. 4294967295 is `(uid_t)-1`, the "no change" value of
  `setresuid` and `chown`, and is rejected as an id.
- `setgroups` is set to `deny` before the gid map, because the kernel
  requires it for an unprivileged gid map (otherwise a process could drop
  a group that denies it access).
- The caller is refused when its effective uid or gid is 0 (an escape
  would yield host root, so the runtime does not offer it) and when real
  and effective ids differ (a setuid or setgid binary would map the
  sandbox onto an id the real user does not own).

Consequences, measured where marked: `setuid` or `chown` to any other id
fails with EINVAL, because the id is not mapped (measured, inside 0 to
12345 and inside 999 to 0: the kernel checks the mapping before the
capability, so root is out of reach as any other id); files of other
owners show as `overflowuid` (measured: `/` shows as 65534); images that
switch users at start (`gosu`, `su-exec`) fail. **The host user's
supplementary groups stay effective** inside (measured: three groups on
the dev host, each visible as `overflowgid`), and `setgroups` cannot drop
them (EPERM, measured). So the runner must run as a dedicated user
without privileged groups; that is a deployment requirement for #8, and
the dev host's user does not meet it.

### D2. Seccomp policy

One fixed policy, no configuration. The filter is a classic BPF program
assembled by `boneli-sys`; classic BPF allows 4096 instructions
(`BPF_MAXINSNS`) and jump offsets of 8 bits (at most 255), and the
assembler checks both. The table below needs about 40 instructions (an
estimate from the rows; PR 4 records the assembler's count). Rows are
read top to bottom, the first match wins. Arguments are read at offset
16 + 8·i of `seccomp_data`, the low 32-bit word on little-endian.

| Match | Action | Why |
|---|---|---|
| `arch` is not the build's `AUDIT_ARCH` (`0xC000003E` on x86_64, `0xC00000B7` on aarch64) | `SECCOMP_RET_KILL_PROCESS` | An i386 `int 0x80` or an AArch32 call uses another syscall table, and i386 `socketcall` would bypass the socket rows. Nothing the runtime runs is 32-bit, so such a call is never legitimate, and killing beats an errno that a probing exploit could branch on. |
| nr > 471 (unsigned) | ENOSYS (38) | Syscalls newer than the reviewed table fail closed. The same row covers x32 numbers (bit 30 set) and nr = −1. ENOSYS makes libc behave as on an older kernel. 471 is the highest number in the Linux 7.2 tables on both architectures (measured: `rseq_slice_yield`). |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | EPERM (1) | Named by the issue. Reachable without capabilities (measured: `io_uring_setup` works unprivileged, `io_uring_disabled` 0), with a long record of privilege escalations. |
| `bpf`, `userfaultfd`, `perf_event_open` | EPERM | Named by the issue. `userfaultfd` widens race windows in kernel exploits; it works unprivileged with `UFFD_USER_MODE_ONLY` (measured). |
| `keyctl`, `add_key`, `request_key` | EPERM | The issue names `keyctl`; the keyring is not namespaced, and the other two reach it without `keyctl` (measured: `keyctl(GET_KEYRING_ID)` works unprivileged). |
| `syslog` | EPERM | The kernel log is not namespaced, and with `kernel.dmesg_restrict` = 0 (the kernel's build default) reading it needs no capability (`check_syslog_permissions`). EPERM is what a restricted host returns already (the dev host has `dmesg_restrict` = 1, measured), so nothing that works today breaks. |
| `clone` or `unshare` with `CLONE_NEWUSER` (0x10000000) in the low 32 bits of arg 0 | EPERM | New user namespaces (named by the issue). `clone` uses only the low 32 bits of its flags; `unshare` rejects unknown upper bits with EINVAL. |
| `clone3` | ENOSYS | Its flags sit behind a pointer that seccomp cannot read. glibc 2.34 and newer fall back to `clone` on ENOSYS, where the row above applies; Docker's profile does the same. |
| `socket` with low32(arg 0) not in {AF_UNIX 1, AF_INET 2, AF_INET6 10, AF_NETLINK 16} | EAFNOSUPPORT (97) | `AF_VSOCK` works in a fresh user and network namespace (measured) and would bypass "no network" on a VM host; other families load protocol modules on demand. Unix, IPv4 and IPv6 carry the brokers (ADR-006: a bound Unix socket, which the shim relays on loopback). `domain` is an `int`, so the low word is the whole value. |
| `socket` with family 16 and low32(arg 2) ≠ `NETLINK_ROUTE` (0) | EPROTONOSUPPORT (93) | Other netlink protocols reach unrelated subsystems (netfilter, audit, generic netlink, uevents, xfrm, crypto), and creating the socket can autoload a module (`request_module` in `netlink_create`). Routing is what glibc's `getaddrinfo` (`AI_ADDRCONFIG`) and `getifaddrs`, libuv's interface list and Chromium's network-change watcher use; inside it reads only the sandbox's own network namespace, and changes need `CAP_NET_ADMIN`. EPROTONOSUPPORT is what `netlink_create` returns for an unavailable protocol, and libaudit reads it as "no audit support", so PAM-based tools keep working. Any further protocol needs a reason in this ADR. |
| `socketpair` with low32(arg 0) ≠ AF_UNIX | EAFNOSUPPORT | Of the four allowed families only AF_UNIX implements `socketpair`; the others create a socket (for netlink possibly autoloading a module) and then fail with EOPNOTSUPP. Docker's current profile allows only AF_UNIX and AF_TIPC (moby/profiles `7b5ccfa`). |
| anything else | allow | Classified one by one in the census (PR 4). Capability-gated calls fail because the workload holds no capability in any namespace (D9), and the census proves each one. |

The syscall numbers the rows use (uapi 7.2.4):

| syscall | x86_64 | aarch64 |
|---|---|---|
| io_uring_setup / enter / register | 425 / 426 / 427 | 425 / 426 / 427 |
| bpf / userfaultfd / perf_event_open | 321 / 323 / 298 | 280 / 282 / 241 |
| add_key / request_key / keyctl | 248 / 249 / 250 | 217 / 218 / 219 |
| syslog | 103 | 116 |
| clone / unshare / clone3 | 56 / 272 / 435 | 220 / 97 / 435 |
| socket / socketpair | 41 / 53 | 198 / 199 |

`AUDIT_ARCH_X86_64` = `EM_X86_64` (62) | `__AUDIT_ARCH_64BIT` (0x80000000) |
`__AUDIT_ARCH_LE` (0x40000000) = 0xC000003E; `AUDIT_ARCH_AARCH64` = 183 |
the same bits = 0xC00000B7. libc 0.2.191 lacks the `AUDIT_ARCH_*`
constants and the syscall numbers 463–471, so `boneli-sys` defines them
locally, each citing its uapi header.

**Extension rule.** Raising the ceiling needs no new ADR: the PR
regenerates the syscall extracts, the completeness test (PR 4) then fails
until every new syscall has a census verdict, and a syscall that matches
a row's criterion joins that row. A new criterion needs a new ADR.

### D3. Kernel floor: Linux 5.19

The runtime requires the newest of the features it uses:
`SECCOMP_RET_KILL_PROCESS` (4.14), `pidfd_send_signal` (5.1), `clone3`
(5.3), `waitid(P_PIDFD)` (5.4), `openat2` (5.6), `CLONE_INTO_CGROUP`
(5.7), `CLOSE_RANGE_CLOEXEC` and overlayfs in a user namespace (5.11),
`cgroup.kill` (5.14), and Landlock ABI 2 (5.19). ABI 2 sets the floor:
under ABI 1 every rename or link into another directory is denied
(`LANDLOCK_ACCESS_FS_REFER` came with ABI 2), and git and npm do both.

`Features::probe` checks the floor by trying each feature, not by reading
`uname`, because distributions backport: a user namespace including the
single id map writes, `clone3`, `close_range` with `CLOSE_RANGE_CLOEXEC`,
`kill_process` through `SECCOMP_GET_ACTION_AVAIL`, the Landlock ABI, cgroup
v2 at `/sys/fs/cgroup`, and delegation of the caller's own cgroup (the
directory, `cgroup.procs`, `cgroup.threads` and `cgroup.subtree_control`
writable, and cpu, io, memory and pids in `cgroup.controllers`). Every
missing feature is reported with a stable id and a message naming its
cause; a failed user namespace is classified from the errno and the
sysctls that explain it (`userns-apparmor`, `userns-disabled`,
`userns-other`). Hosts below the floor are refused: RHEL 9 (5.14) and
Ubuntu 22.04 GA (5.15) are out.

### D4. Spawn model

`spawn(&Spec)` starts the program in four phases, all in the calling
process until the clone:

1. **Refuse** callers with euid or egid 0 and callers whose real and
   effective ids differ (D1), a relative program path (no `PATH` search),
   a zero setup timeout (no default: the caller sizes it), NUL bytes and
   environment names that are empty or contain `=`.
2. **Prepare** every byte the child needs: the program, `argv` (the
   program path, then the arguments) and `envp` as C strings and pointer
   arrays, the map lines, and the three stdio descriptors duplicated to
   numbers of at least 3 with close-on-exec (so no `dup2` in the child can
   overwrite a source a later one needs).
3. **Clone**: a close-on-exec report pipe, then a raw `clone3` with
   `CLONE_NEWUSER | CLONE_PIDFD`, `exit_signal = SIGCHLD` and no stack, so
   the child continues on its copy of the parent's stack, as after `fork`.
4. **Wait for the report** with `poll` until the setup timeout; on
   timeout the child is killed through its pidfd and reaped.

The child runs a fixed sequence (`Step`): `deny` to `/proc/self/setgroups`,
the gid map, the uid map; `setsid` (a new session without a controlling
terminal); every signal disposition 1–64 except SIGKILL and SIGSTOP to
`SIG_DFL` through the raw `rt_sigaction`, then an empty signal mask (in
this order, so no parent handler can run in the child; std ignores
SIGPIPE, and an ignored disposition survives `execve`); `dup2` of the
three stdio descriptors; `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`, so no
other descriptor reaches the program (the CVE-2024-21626 class), while
the report pipe stays open until the exec itself; `execve` with exactly
the spec's environment.

**The child allocates nothing and takes no lock.** It is a copy of one
thread of a process whose other threads may have held the allocator's or
any other lock at the moment of the clone, and that copy of the lock
stays held forever. Every failure is a fixed-size value; nothing is
formatted. The tests run with an allocator that exits with 97 when called
from a pid other than the one it recorded, so an allocation in the child
fails every test deterministically instead of deadlocking sometimes.

**Report protocol, fail closed.** EOF with no bytes means the exec
succeeded (the close-on-exec pipe closed). Exactly 12 bytes
(`step: u32, index: u32, errno: i32`, little-endian) mean a step failed;
the child exits 127 right after, and the parent reaps it and returns
`Error::Setup { step, index, errno }`, rendered as
`setup step <name> (item <index>) failed: <strerror>`. Any other length
or an unknown step code is `Error::Protocol`; the child is killed and
reaped. A child that dies before writing its report (the allocation guard
in tests) also closes the pipe with no bytes, which the parent cannot
tell from an exec; its exit code (97 or 127) shows it.

**Waiting and killing** go through the pidfd (`waitid(P_PIDFD)`,
`pidfd_send_signal`), so a recycled pid is never hit. A second wait is an
error. Dropping a `Child` that was not waited for kills and reaps it, so
a sandbox never outlives its handle unnoticed.

**No `PR_SET_PDEATHSIG`.** It fires when the *thread* that created the
child exits, not the process, and the runner spawns sandboxes from worker
threads; a sandbox would die whenever its worker thread ended. Orphan
cleanup after a runner crash is #33.

**Why `clone3` and not `std::process::Command`:** `pre_exec` runs after
the fork, so it cannot put the child itself into a new PID namespace
(`unshare(CLONE_NEWPID)` affects only later children) or into its cgroup
atomically (`CLONE_INTO_CGROUP`, PR 3).

### D5. Tests and CI

- **Kinds.** Tests that create a namespace, a cgroup or a filter, or
  apply Landlock, are `#[ignore = "host: <features>"]`; `cargo test
  --workspace` lists them as ignored with that reason. Pure tests (ids,
  report decoding, step codes, probe messages and classification, the
  host-setup block) run in `check`.
- **One integration test target**, `tests/boneli_sys_tests/`, so that the
  binaries that need user namespaces are exactly two: `boneli_sys-<hash>`
  (unit tests) and `boneli_sys_tests-<hash>`. Host tests re-execute their
  own binary inside the sandbox as a probe (`--exact probe --nocapture`,
  `BONELI_SYS_PROBE=<action>`), which prints `key=value` lines.
- **Running.** `cargo test -p boneli-sys -- --ignored` never skips: a
  missing feature fails with the probe's message. The only leniencies are
  visible: `BONELI_SYS_HOST_GAPS` (set in the workflow file, so reviewed;
  exact per host; empty until PR 4), Landlock rows above the kernel's ABI
  (PR 4), and `Unproven` census entries (PR 4), all printed outside
  libtest's capture.
- **CI.** The job `sandbox` runs on `ubuntu-latest` (x86_64) and
  `ubuntu-24.04-arm` (aarch64, the only runtime check of the aarch64
  tables). It first runs the probe test on the stock runner with
  `BONELI_SYS_EXPECT_MISSING` set to the exact set a stock runner lacks,
  so the error users hit on an unprepared host is itself tested; then it
  prepares the host with the host-setup block from `CLAUDE.md`, the same
  block users run (the workflow has no privileged step of its own); then
  it runs every host test in a delegated `systemd-run --user` scope. The
  `check` job also runs `cargo check -p boneli-sys --all-targets` for
  `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, because
  the shim (#9) ships as a static musl binary and libc's constants differ
  per target.
- **AppArmor.** Ubuntu 23.10 and newer restrict unprivileged user
  namespaces through AppArmor. Instead of switching the restriction off
  for the whole host (the sysctl), the host-setup block loads a profile
  that allows `userns` only for the two test binaries:
  `$TARGET_DIR/*/deps/boneli_sys{,_tests}-[0-9a-f]*`, unconfined
  otherwise. `probe::apparmor_profile_is_narrow` proves the rest of the
  host keeps the restriction: a copy of the test binary outside that path
  must still report `userns-apparmor`. The profile is path-based, and the
  building user can write those paths, so on a shared or desktop host it
  lifts the restriction for that user; CI runners are ephemeral and
  single-purpose, and a production runner needs a root-owned binary path
  (#8). `TARGET_DIR` must match `[A-Za-z0-9._/-]`, before and after
  `realpath` (AppArmor matches the resolved exec path), and must not be
  `/`: the character set keeps AppArmor glob and quoting characters out
  of the profile, and `/` would turn the glob into one over the whole
  filesystem.
- **cgroups.** The block delegates cpu, io, memory and pids to user
  managers with a drop-in for `user@.service` (systemd delegates io only
  on request: a `systemd-run --user --scope` without `Delegate=yes` has
  no io controller, measured), and on headless hosts enables linger so a
  user manager exists, restarts it so the delegation applies, and waits
  for its bus. The wait is bounded at 30 s as a hang bound, not a target;
  the time CI measured is recorded below.
- **Why a shell block, not a program.** These are administration
  commands a user types once with root; a program would hide them behind
  a binary the user has to trust with `sudo`. The block is tested
  against a fake `sudo` (`host_setup::resolves_and_rejects_target_dirs`).
- **Assumptions the first CI run verifies** (recorded as measured below):
  the stock runners restrict user namespaces through AppArmor and do not
  delegate the job's cgroup, so they lack exactly `userns-apparmor` and
  `cgroup-not-delegated`; linger plus the drop-in gives a delegated scope
  with io; `ubuntu-24.04-arm` is available to this public repository;
  Landlock is enabled. If the arm runner is unavailable, aarch64 runtime
  coverage is a stated gap here, and `check` still compiles both musl
  targets.
- **Dev host.** Landlock rows above the CI kernel's ABI, the rows in
  `BONELI_SYS_HOST_GAPS`, and the timing-sensitive cgroup tests run on a
  second machine; each PR of #6 carries the dev-host summary.

CI measurements (first run of PR 1): to be filled in from the run.

### D6. Lints of the unsafe crate

`boneli-sys` cannot inherit the workspace lints, which forbid
`unsafe_code`, so it has its own `[lints]` table. Nothing checked that
the copy kept the other workspace lints: the root `Cargo.toml` only says
that `boneli-sys` "opts out of these lints explicitly". Two of them matter
more here than anywhere: `unwrap_used` (a panic in the cloned child
aborts it mid-setup without a report) and the documentation rule. The
architecture check gets the rule `sys-lints`: every crate in
`roles.unsafe` has its own `[lints]` table (`workspace = true` fails)
holding every `workspace.lints` entry except `rust.unsafe_code` at the
same or a stricter level (allow < warn < deny < forbid, string or
`level` form), every lint of the new `[check] unsafe-lints` array in
`tools/architecture.toml` at `deny` or `forbid`, and no other entry below
`deny` (an allowed lint group with a higher `priority` would otherwise
override a required lint). The array is required, so deleting it is a
`policy-format` failure rather than a silent weakening. Its lints:

- `rust.unsafe_op_in_unsafe_fn`: every unsafe operation sits in an
  explicit `unsafe` block, also inside an `unsafe fn`;
- `clippy.undocumented_unsafe_blocks`: every block carries a
  `// SAFETY:` comment;
- `clippy.multiple_unsafe_ops_per_block`: one operation per block, so
  each comment justifies exactly one operation.

The checker stays Python per ADR-001 D4 (its Rust port is #35).

## Consequences

- `boneli-sys` depends on `libc` only (the edge `boneli-sys -> libc` is
  ADR-001's) and assembles the seccomp program itself; no new crate.
- The runtime needs Linux 5.19 and a host prepared for unprivileged user
  namespaces and cgroup delegation. Stock Ubuntu 23.10+ hosts need the
  AppArmor profile, and RHEL 9 and Ubuntu 22.04 GA are out.
- One id inside: images that switch users fail, and the runner must be a
  dedicated user without privileged supplementary groups.
- The host-setup block runs with root, on CI and on user hosts. It is
  reviewed like the workflow and tested against a fake `sudo`; the tests
  and the runtime never use `sudo`.
- The AppArmor profile is path-based (D5).
- CI gets a job that runs on two architectures and prepares its host.

## Alternatives considered

- **Crates `seccompiler`, `landlock`, `caps`, `nix`.** Each is a new crate
  name under ADR-001, and `libc` has everything except the Landlock and
  audit constants and the newest syscall numbers, which are a handful of
  constants with header citations.
- **`std::process::Command` with `pre_exec`.** Cannot place the child
  itself into a new PID namespace or into a cgroup atomically (D4).
- **Subordinate id ranges** (`newuidmap`). Would allow several ids inside,
  but needs setuid helpers on the host, which ARCHITECTURE excludes.
- **A configurable policy.** Every sandbox runs untrusted code under the
  same threat; a per-run knob is a way to weaken it by mistake.
- **An allowlist filter** (deny everything not listed). It breaks every
  new syscall a libc or runtime adopts, and Docker's own allowlist
  already lags the kernel (its last sync is "profiles/seccomp: kernel
  v6.13"); the ENOSYS ceiling gives the same fail-closed behavior for
  unknown calls, and the census (PR 4) reviews every known one.
- **Switching the AppArmor restriction off host-wide**
  (`kernel.apparmor_restrict_unprivileged_userns=0`). Simpler, but it
  lifts the restriction for every program on the host; the narrow profile
  keeps it for everything but the two test binaries.
- **A CI-only privileged setup step.** It would test a host that no user
  has; running the documented block keeps CI and users on one path.
- **A floor of 5.15 (Ubuntu 22.04 GA)** with Landlock ABI 1. ABI 1 denies
  cross-directory renames and links, which git and npm need.
- **One PR for all of #6.** This crate is the security boundary, and #28
  took four review rounds on one surface; four PRs keep each review
  bounded.
