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
`kill_process` through `SECCOMP_GET_ACTION_AVAIL`, an allow-all seccomp
filter with `PR_SET_NO_NEW_PRIVS`, installed by a probe child of its own
that is cloned without a new user namespace (`SECCOMP_GET_ACTION_AVAIL`
alone also succeeds on a kernel with `CONFIG_SECCOMP` but without
`CONFIG_SECCOMP_FILTER`, review of PR 1; `seccomp-filter` only when the
child's own filter step fails or its install hangs; it runs as
`Step::Seccomp`, which `spawn` gets in PR 4. A separate child, so that a
host lacking both filters and user namespaces is told about both: the
probe reports the exact missing set), the Landlock ABI, cgroup
v2 at `/sys/fs/cgroup` mounted with `nsdelegate` (since PR 3,
`cgroup-nsdelegate`, D8), and delegation of the caller's own cgroup (the
directory, `cgroup.procs`, `cgroup.threads` and `cgroup.subtree_control`
writable, and cpu, io, memory and pids in `cgroup.controllers`). Every
missing feature is reported with a stable id and a message naming its
cause; a failed user namespace is classified from the errno and the
sysctls that explain it (`userns-apparmor`, `userns-disabled`,
`userns-other`). A failure of a probe's own machinery, not the feature it
tests — a failed `pipe2`, `poll`, `read` or `waitid`, a malformed report,
a probe child killed by a signal or ended by the test allocation guard,
or a `clone3` that fails for a resource (`EAGAIN` from `RLIMIT_NPROC` or
the scope's `pids.max`, `ENOMEM`) rather than for a reason that says
something about user namespaces (`EPERM`, `EACCES`, `ENOSPC`, `EINVAL`) —
is reported as `probe-failed` with the stage and the cause, never as the
feature itself, so a host near `RLIMIT_NOFILE` or `RLIMIT_NPROC` is not
told its user namespaces or seccomp are broken, and both children
classify the same resource error the same way (review of PR 1 and PR 2;
`classify_ids_failure`, `classify_filter_failure`). Under AppArmor's restriction an unconfined process still
creates the namespace, but without capabilities in it, so opening
`/proc/self/setgroups` fails with EACCES (measured on both CI runners); a
confined profile without `userns` fails the clone with EPERM. Both count
as `userns-apparmor` when the sysctl is 1. Hosts below the floor are refused: RHEL 9 (5.14) and
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
3. **Clone**: a close-on-exec report pipe whose write end is moved to a
   number of at least 3 (a caller with 0-2 closed would otherwise get it
   there, the child's stdio `dup2` would replace it, and every later
   failure would be written into the program's stdio and read as an exec;
   review of PR 1, reproduced). Then every signal is blocked on the
   calling thread, a raw `clone3` with `CLONE_NEWUSER | CLONE_PIDFD` (since PR 2 with the
   namespaces of D7 too, since PR 3 with `CLONE_INTO_CGROUP`, D8),
   `exit_signal = SIGCHLD` and no stack runs, so the child continues on
   its copy of the parent's stack, as after `fork`, and the parent
   restores its mask right after the clone (glibc's `posix_spawn` does
   the same).
4. **Wait for the report** with `poll` until the setup timeout; on
   timeout the child is killed through its pidfd and reaped.

The child runs a fixed sequence (`Step`): `deny` to `/proc/self/setgroups`,
the gid map, the uid map; the cgroup namespace, the root, the mounts,
`pivot_root`, the hostname and `lo` (D7, PR 2); `setsid` (a new session without a controlling
terminal); every signal disposition 1–64 except SIGKILL and SIGSTOP to
`SIG_DFL` through the raw `rt_sigaction` while every signal is still
blocked, then an empty signal mask. So no parent handler can run in the
child: from the clone until the dispositions are reset nothing is
delivered (without the block, a handler ran in the child during the map
writes, review of PR 1), and after it every disposition is the default.
std ignores SIGPIPE, and an ignored disposition survives `execve`, which
is why every signal is reset; `dup2` of the
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
  host-setup block, inside paths, hostnames, mount order and the mount
  plan, the overlay option limit; since PR 3 the cgroup limits, their
  rendering, cgroup names and the mountinfo decoding and device mapping)
  run in `check`.
- **Fixture roots** (PR 2). Every host test runs in a full sandbox on a
  fixture root under `CARGO_TARGET_TMPDIR`: a base layer with the mount
  points, the host's `/usr` (and `bin`, `lib`, `lib64`, `sbin` as the
  symlinks they are on the host, or bound where they are directories)
  and the test binary bound read-only at `/probe`, a writable
  `/workspace`, a tmpfs `/tmp`, `/proc` and `/dev`; `etc/ld.so.cache` is
  copied from the host for the dynamic loader. The unit tests use a root
  next to the test binary with one mount of every kind, so a fault at
  every step is reached.
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
  that allows `userns` only for the two test binaries,
  `$TARGET_DIR/*/{deps,build/boneli-sys/[0-9a-f]*/out}/boneli_sys{,_tests}-[0-9a-f]*`,
  unconfined otherwise. The two alternatives are cargo's two layouts:
  `deps/` before cargo 1.100, and `build/<package>/<hash>/out/` since
  (measured: the CI runners' cargo 1.100 put the test binaries there,
  and the first CI run failed on a profile that named only `deps/`).
  `probe::apparmor_profile_is_narrow` proves the rest of the host keeps
  the restriction: a copy of the test binary outside that path must still
  report `userns-apparmor`. A program the profile execs stays in the
  profile (a copy the test binary started itself was not restricted on
  the CI runners), so the test has the user manager start the copy
  (`systemd-run --user`) and checks both labels: the test binary runs as
  `boneli-sys-tests`, the copy does not. The same inheritance means that
  everything a test sandbox runs is under the profile too. The profile is path-based, and the
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

**CI measurements** (first runs of PR 1, 2026-11-13; the "Host
features" step prints them on every run):

| | `ubuntu-latest` | `ubuntu-24.04-arm` |
|---|---|---|
| kernel | 7.0.0-1019-azure x86_64 | 7.0.0-1017-azure aarch64 |
| LSMs | lockdown, capability, landlock, yama, apparmor, bpf, ima, evm | lockdown, capability, landlock, yama, apparmor, ima, evm |
| `kernel.apparmor_restrict_unprivileged_userns` | 1 | 1 |
| `kernel.dmesg_restrict` / `perf_event_paranoid` / `unprivileged_bpf_disabled` | 1 / 4 / 2 | 1 / 4 / 2 |
| the job's cgroup | `system.slice/hosted-compute-agent.service`, owned by root, controllers cpuset cpu io memory pids | the same |
| stock runner lacks (step 3) | exactly `userns-apparmor`, `cgroup-not-delegated` | the same |
| host-setup block (linger, restart, bus wait) | 1 s | 1 s |
| after the block, in a `Delegate=yes` scope | nothing missing (io included) | the same |
| cgroup2 super options (since PR 3) | `nsdelegate` present | the same |

Every assumption above held but one: the AppArmor restriction shows as
EACCES at the setgroups open, not EPERM (D3). The runner user has
supplementary groups (`adm`, `docker`, `systemd-journal`), which stay
effective inside the sandbox (D1); on CI that is accepted, a production
runner must not have them. The 30 s bound of the bus wait is 30 times the
measured start.

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
`tools/architecture.toml` at `forbid`, and no other entry below `deny`
(an allowed lint group with a higher `priority` would otherwise override
a required lint). The array is required, so deleting it is a
`policy-format` failure rather than a silent weakening.

Why `forbid` and not `deny`: cargo passes the `[lints]` table to rustc as
command-line levels, and an inner attribute in the source
(`#![allow(clippy::undocumented_unsafe_blocks)]`, or `#[allow]` on one
function) overrides every command-line level except `forbid`. At `deny`
such an attribute passed both clippy and the architecture check (review
of PR 1 of #6, reproduced); at `forbid` it is error E0453. The crate has
no `allow` attribute, so `forbid` costs nothing. Its lints:

- `rust.unsafe_op_in_unsafe_fn`: every unsafe operation sits in an
  explicit `unsafe` block, also inside an `unsafe fn`;
- `clippy.undocumented_unsafe_blocks`: every block carries a
  `// SAFETY:` comment;
- `clippy.multiple_unsafe_ops_per_block`: one operation per block, so
  each comment justifies exactly one operation;
- `clippy.unwrap_used`: no unwrap, because a panic in the cloned child
  aborts it mid-setup without a report (the workspace has it at `deny`;
  here it is `forbid` like the rest).

The checker stays Python per ADR-001 D4 (its Rust port is #35).

### D7. Namespaces, mounts and the brokers

Added by PR 2 of #6; measurements on the dev host on 2026-11-14 unless
they name CI.

**Namespaces.** `clone3` creates user, mount, PID, network, IPC and UTS
namespaces at once (`CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS`), so the program is PID 1 of
its own PID namespace from its first instruction; `unshare(CLONE_NEWPID)`
after a fork would only affect later children (D4). The cgroup namespace
is the exception: `copy_process` creates namespaces before it moves the
child into its target cgroup, so a cgroup namespace from `clone3` would
be rooted at the parent's cgroup (from the kernel source, not measured).
That reading missed `cgroup_post_fork()`, which re-roots a new cgroup
namespace at the `CLONE_INTO_CGROUP` target since Linux 5.7 (D8), so with
placement at the clone both orders are equivalent.
The child creates it with `unshare(CLONE_NEWCGROUP)` right after the id
maps (`Step::CgroupNs`); since PR 3 `clone3` has put the child into its
cgroup with `CLONE_INTO_CGROUP` before this step, and
`cgroup_namespace_root_is_sandbox_cgroup` pins the order (D8). The probe's id
child keeps creating only a user namespace and its filter child none
(D3).

**The steps**, between the id maps and `setsid` (D4), each a `Step` with
its own report code, the item being the mount's index in `Root::mounts`
(for `Pivot` the sub-call, 0-4):

1. `CgroupNs`, as above.
2. `MakePrivate`: `mount("/", MS_REC | MS_PRIVATE)`, so nothing the
   sandbox mounts propagates to the host and `pivot_root` accepts the
   tree. (The kernel already turns copied shared mounts into slaves for a
   less privileged mount namespace, and a host-side mount event needs
   privileges, so no test can tell; `mount_step_order` pins the step.)
3. `Root`: the root on the staging directory, read-only, `nosuid`,
   `nodev`. One layer is bound (`open_tree(OPEN_TREE_CLONE)`, not
   recursive, then `mount_setattr`, then `move_mount`), because overlayfs
   refuses a single `lowerdir` without an `upperdir` (EINVAL, measured at
   planning). Several layers become an overlay with `userxattr`, because
   an unprivileged unpacker (#7) can write only `user.*` xattrs; each
   layer is opened symlink-free and named in `lowerdir` by its descriptor
   (`/proc/self/fd/<n>`, see Path resolution), top layer first.
4. `MountTarget` and the mount, for every entry of `Root::mounts` in
   order (below).
5. `Pivot`: `fchdir` to the new root, `pivot_root(".", ".")`, `umount2(".",
   MNT_DETACH)` (the old root and every host mount under it go at once),
   `chdir("/")`, `chdir(cwd)`. The program path is resolved after this,
   inside the root (`program_resolves_inside_the_root`).
6. `Hostname`: `sethostname` in the new UTS namespace.
7. `Loopback`: `lo` up with `SIOCGIFFLAGS` and `SIOCSIFFLAGS` on an
   `AF_INET` datagram socket, so the pod and the shim's broker relay have
   127.0.0.1. The network namespace has nothing else (measured: the only
   interface is `lo`, TCP on 127.0.0.1 works, a connect to TEST-NET-1
   gives ENETUNREACH).

**Mounts** (`Mount`). Every target is an `InsidePath`: absolute, no `.`,
`..` or empty component, no NUL, never `/`; no two mounts share a target,
and a mount may not hide an earlier one (a later mount of an ancestor of
its target), because the hidden mount would be invisible but still
configured. Targets must exist in the root: the image or the top layer
(#8) provides mount points; a missing one fails with ENOENT and its index.

- `Bind { source, target, writable }`: a host file or directory, not
  recursive; the target must be of the same kind (a directory onto a
  directory, anything else onto a non-directory, such as a broker socket
  onto an empty file), else `Step::Bind` with ENOTDIR or EISDIR and the
  index. `mount_setattr` *adds* `nosuid`, `nodev` and `ro` unless writable,
  never clears a flag, so the flags the kernel locked on a mount copied
  from a more privileged namespace stay (`ro_bind_keeps_locked_flags`:
  a read-only bind of `/dev/shm` keeps its `nosuid,nodev`). The fallback
  the plan kept for a refused `mount_setattr` on a detached tree is not
  needed: it works in a user namespace (measured).
- `Tmpfs { target, size_bytes, mode }`: `nosuid,nodev`. Exec stays
  allowed on tmpfs, overlay and bind mounts, because test runners
  execute from `/tmp` and `/workspace`.
- `Overlay { lower, upper, work, target }`: a writable overlay with
  `userxattr`, `nosuid,nodev`; writes land in `upper`, `lower` is
  unchanged (`writable_overlay_mount`).
- `Proc { target }`: `nosuid,nodev,noexec`, mounted before `pivot_root`,
  because the kernel lets a user namespace mount a new procfs only while
  a fully visible one is in its mount namespace.
- `Dev { target, shm_size_bytes }`: the OCI default devices without
  `/dev/console`. A tmpfs of 64 KiB, mode 0755, `nosuid,noexec`, holding
  `null`, `zero`, `full`, `random`, `urandom` and `tty` bound from the
  host's nodes (`nosuid,noexec`, not `nodev`: they are devices), a
  `devpts` with `newinstance,ptmxmode=0666,mode=0620`, the directories
  `pts` and `shm` and the symlinks `ptmx -> pts/ptmx`, `fd`, `stdin`,
  `stdout`, `stderr`; then the tmpfs is made read-only (13 entries,
  `dev_minimal`; writing `/dev/null` and `posix_openpt` work, creating a
  file gives EROFS). `shm` is a tmpfs of `shm_size_bytes`,
  `nosuid,nodev,noexec`, for PostgreSQL's dynamic shared memory. 64 KiB:
  the entries need no data pages (measured: 0 bytes used), so the number
  only bounds a tmpfs that is read-only once filled; any size above 0
  works, and 0 would mean unlimited.

**Sizes have no default and 0 is refused**, because a tmpfs of size 0 is
unlimited; #8 sets the values, as with ADR-003's limits. A tmpfs of
1,048,576 bytes takes a file of exactly that size, and one byte more
gives ENOSPC (measured, `tmpfs_size_inclusive`): the kernel charges whole
pages of data, nothing for the inode.

**Mount options fit one page**, 4096 bytes with the NUL: `mount(2)` copies
its data argument as one page, and 4096 is the x86_64 page and the
smallest arm64 page, so a longer string would work on some hosts and not
others. The overlay options name the opened descriptors (below), so each
layer renders as `/proc/self/fd/<n>`, at most 24 bytes (the 14-byte prefix
plus the ten decimal digits of an `i32`), with a `:` between layers. The
worst case for N layers is `lowerdir=` (9), N fd paths of 24 bytes and
N − 1 separators, `,userxattr` (10) and the NUL:
`9 + 24·N + (N − 1) + 10 + 1 = 25·N + 19 ≤ 4096`
(`root_overlay_options_len`; PR 2 wrote it as `9 + 25·N + 11`, which
counts one separator too many and gives the same cap). That caps the root
overlay at **163 lower layers** (4094 bytes; 164 take 4119), checked in the
parent (`Error::MountOptionsTooLong` before the clone;
`overlay_option_page_limit` pins 163 fitting and 164 not). That cap also
bounds the descriptors the child holds open at once. A writable
`Mount::Overlay` names three descriptors and always fits. The layer and
overlay directory paths are still required to be UTF-8 and free of `,`,
`:` and `\` as input hygiene matching the rest of the path validation,
though with fd-path options they no longer reach overlay's option parser
(`overlay_non_utf8_path_rejected`).

**Path resolution.** Targets are opened with `openat2(root,
<target>, O_PATH, RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS)` beneath the new root and mounted onto
`/proc/self/fd/<n>` (a stack buffer, no allocation), so a target swapped
for a symlink cannot redirect a mount out of the root (the CVE-2021-30465
class): a symlink anywhere in a target, the last component included,
fails with ELOOP (`mount_target_symlink_rejected`). The plan had
`O_NOFOLLOW` too; it is left out because with it `openat2` returns a
descriptor of a trailing symlink itself instead of failing (measured, as
openat2(2) documents), and the mount would then land on the symlink's
inode. Every host path the child hands to the kernel is opened in the
child with `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` first, so a
symlink in it fails with ELOOP and callers pass canonical paths: bind
sources (`bind_source_symlink_rejected`), the staging directory, every
root overlay layer (`root_layer_symlink_rejected`), and `Mount::Overlay`'s
`lower`, `upper` and `work` (`overlay_dir_symlink_rejected`). overlayfs
and `mount(2)` resolve a path argument with `LOOKUP_FOLLOW`, so a path
that is only checked and then mounted by name is a check-then-use race: a
host thread swapping the path for a symlink between the two wins (review
of PR 2, round 2, measured: a writable overlay's `upper` and a root layer
both escaped). So the opened descriptor must be what the mount uses, not a
re-resolved path. For a bind that is `open_tree` on the fd. For an overlay
the child keeps every opened descriptor open across the mount and names it
in the options as `/proc/self/fd/<n>`; the kernel follows that `/proc`
link to the exact inode that was opened symlink-free, so the swap cannot
redirect a layer or directory (overlay accepts fd-path options in a user
namespace, measured; `overlay_upper_swap_race_never_escapes`,
`root_layer_swap_race_never_escapes` win zero of 120 spawns each while a
thread swaps). The descriptors are CLOEXEC, held in a fixed-size set, and
the child allocates nothing; once `mount(2)` returns the kernel has pinned
the inodes and they are closed. The plan opened bind sources in the
parent; that cannot work: `open_tree(OPEN_TREE_CLONE)` on a descriptor
opened in the parent's mount namespace fails with EINVAL in the child's
new one (measured), so the child opens them from the prepared path.

**The root is read-only** (`root_is_read_only`: `/etc/x` and `mkdir /new`
give EROFS, `/workspace` and `/tmp` are writable); a writable root for a
prepare phase is #8's decision. After `pivot_root` only the root and the
spec's mounts are in `mountinfo`, a host file outside every layer is
unreachable by its host path and via `/..`, and `/proc/1/root` is `/`
(`pivot_root_hides_host`).

**Brokers** (ADR-006). The network namespace has only `lo`; the sandbox
reaches the egress proxy through a pathname Unix socket that #8
bind-mounts into the sandbox (the socket file, or its directory). A
pathname socket is found through the filesystem, so `connect` reaches the
host listener from any network namespace, also through a read-only bind
(measured for inside ids 0 and 999, `broker_socket_reachable_through_ro_bind`);
the shim (#9) relays it on loopback for `HTTPS_PROXY`. The socket must be
writable by the host user the inside id maps to; the egress running as
the runner's user gives that through the owner bits. Host abstract
sockets are unreachable (ECONNREFUSED, `host_abstract_sockets_unreachable`),
because the abstract namespace belongs to the network namespace. Pods
sharing a network namespace come in #8; joining a namespace owned by
another user namespace needs `CAP_SYS_ADMIN` over its owner, so a pod
shares one user namespace.

**Overlay whiteouts** (for #7): a 0:0 character device in an upper layer
hides the file below and `user.overlay.opaque=y` hides a directory below
(`overlay_layers_whiteout_and_opaque`); an unprivileged user may create
the 0:0 whiteout (allowed, measured; Linux 5.8 lifted `CAP_MKNOD` for it).

### D8. cgroups

Added by PR 3 of #6; measurements on the dev host (Linux 7.2.10, btrfs
with `compress=zstd:1` on dm-crypt on NVMe) on 2026-11-14 unless they
name CI.

**Delegation.** Every sandbox gets a cgroup of its own under a delegated
cgroup v2 parent (`Parent`). `Parent::open(path)` refuses a directory that
is not on cgroup v2 (`fstatfs`, `CGROUP2_SUPER_MAGIC` 0x63677270,
`Error::NotCgroup2`) or whose `cgroup.subtree_control` lacks cpu, io,
memory or pids (`Error::ControllerMissing` with the first missing one in
that order, the same order as the host probe), because a sandbox never
runs without all four limits (`parent_without_controllers_rejected`, also
for each controller missing alone). A delegated scope or service starts
with its own processes in it, and the kernel enables controllers for
children only in a cgroup without processes (the no-internal-process
rule), so `Parent::vacate_and_delegate(path)` moves every pid of
`cgroup.procs` into `path/leaf` and then writes `+cpu +io +memory +pids`
to `cgroup.subtree_control` (`vacate_moves_every_process`). A process
forked into `path` between the moves and the write makes it fail with
EBUSY; the moves are retried 3 times, which covers a parent forking a
helper at that moment, while a parent that keeps forking into its own
cgroup is a bug the error then shows. A production runner calls it once
in its own `Delegate=yes` service (#8). The harness calls it only with
`BONELI_SYS_TEST_CGROUP=self` (D5), so a terminal's cgroup is never
reorganized; a later test binary of the same run starts in `leaf/` and
opens its parent instead. A `systemd-run --user --scope -p Delegate=yes`
scope has all four controllers on the dev host (without `Delegate=yes`
there is no io, measured at planning) and on both CI legs (D5).

**One descriptor per directory, no path used twice.** The parent is
opened once (`openat2` with `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`,
so callers pass canonical paths, as for the mounts in D7); `leaf/` and
every sandbox cgroup are created with `mkdirat` on that descriptor and
opened with `openat(O_DIRECTORY | O_NOFOLLOW)` on it, and every file
(`cgroup.procs`, `cgroup.subtree_control`, the limits, `cgroup.kill`,
`cgroup.events`) is opened relative to the directory's descriptor with
`O_NOFOLLOW`; the cgroup is removed with `unlinkat` on the parent's
descriptor. `clone3` names the cgroup by its descriptor
(`clone_args.cgroup`), so nothing the kernel places the child in is
resolved by name after it was checked. This applies the lesson of D7's
check-then-mount race. What is left: between `mkdirat` and `openat` a
process of the same host user could remove the new directory and create
another of the same name; the descriptor opened then is checked to be on
cgroup v2 and gets every limit written and read back, so it is at worst a
fresh, fully limited cgroup. Only the runner's own user can do it, and the
sandbox, which runs as that user, has no view of the host's cgroupfs
(below). The paths `Parent::path` and `Cgroup::path` exist for messages
and for reading statistics; nothing is opened through them again.
`block_device_of` reads `/proc/self/mountinfo` and stats a device node by
name, but only to find a device number; nothing found there is mounted.

**Limits** (`Limits`, no `Default`: #8 sizes every one, as with the sizes
of D7):

- `memory_max` at least one page, read at run time with
  `sysconf(_SC_PAGESIZE)`, because the kernel rounds memory limits down to
  a page and arm64 pages may be 4, 16 or 64 KiB; below one page the limit
  would read back as 0. `33554433` reads back `33554432` (measured;
  `limit_files_render_and_read_back`). Huge pages are charged to `memory.max`
  only when cgroup2 is mounted with `memory_hugetlb_accounting` (Linux
  6.6, off by default), which the arm64 CI runner lacks (measured; the dev
  host and the x86_64 runner have it), so PR 4's seccomp rows refuse
  `MAP_HUGETLB`, `SHM_HUGETLB` and `MFD_HUGETLB`.
- `memory_swap_max` any value, 0 for no swap; also rounded down to a page
  (measured).
- `pids_max` at least 1: the kernel accepts 0 (measured), which leaves the
  sandbox unable to start, so it can only be a mistake. `pids.max` counts
  tasks, threads included (`pids_limit_exact`: with 8 and T threads, the
  probe forks exactly 8 − T children, then EAGAIN). **Note for #8:** the
  shim's broker relay (#9) runs inside the sandbox, so its threads count
  against `pids.max`; ADR-006 D9 allows the egress 64 connections, and a
  relay with a thread per connection needs that many tasks on top of the
  workload's.
- `cpu: CpuMax { quota_us, period_us }`, quota at least 1000 µs and
  period 1000..=1,000,000 µs: the kernel's bounds (measured: `999 1000`
  and period 999 or 1,000,001 give EINVAL, `1000 1000` and period
  1,000,000 work). There is no `max` quota: a sandbox never runs without a
  CPU limit.
- `io: IoLimits`, a list of `IoMax { dev, rbps, wbps, riops, wiops }`, at
  most one per device; an unset field renders as `max`, every entry sets
  at least one field (an all-`max` line is no limit and does not even
  appear in `io.max`, measured), and no field is 0 (the kernel answers
  ERANGE, measured). Each write carries all four fields, because the kernel
  merges a partial line with the device's earlier values (measured).
  `IoLimits::none()` is explicit: a sandbox whose writable files are on
  tmpfs has no block device to limit, and #8 decides when one is required.
  `dev` must be a whole disk: the kernel throttles per disk and gives
  ENODEV for a partition (measured at planning).
- `memory.oom.group` is always 1: a partial OOM kill leaves a half-dead
  pod (PostgreSQL gone, the application alive) whose test results
  mislead. `memory_limit_kills_whole_group`: with `memory.max` 32 MiB and
  no swap, a child of the probe touches 64 MiB (twice the limit, so the
  overshoot is unambiguous) while the probe, PID 1 of the sandbox, waits;
  both die with SIGKILL, and `memory.events` counts `oom_group_kill` ≥ 1
  and `oom_kill` ≥ 2. PID 1 waits and the child touches (the plan had it
  the other way round), because when PID 1 dies the kernel kills the
  whole PID namespace anyway, which would hide a missing group kill.
- **`oom_score_adj` at least 0** (`Step::OomScoreAdj`, code 23, right
  after the id maps; review of PR 3). The value is inherited across
  `clone`, and the OOM killer skips tasks at `-1000`
  (`oom_kill_memcg_member` and `oom_badness`), so under a runner started
  with `OOMScoreAdjust=-1000` a memcg OOM in the sandbox would kill
  nothing: `memory.max` still holds, but the sandbox stalls in reclaim
  instead of dying as one group, the half-dead pod above. The child reads
  the inherited value into a stack buffer and writes `0` if it is
  negative, never lowering it: raising needs no capability, lowering
  needs `CAP_SYS_RESOURCE`, so the workload cannot go below what it got
  either. 0 rather than a higher value: it removes the exemption without
  ranking the sandbox before the host's own processes. The decision is
  pinned by `oom_score_adj_raised_never_lowered` (pure; a negative value
  cannot be set without `CAP_SYS_RESOURCE` on a test host), and
  `oom_score_adj_never_lowered` checks on the host that a runner at 500
  keeps 500 inside and that this process's own value is kept.

**Ordering.** `Cgroup::create(&Parent, name, &Limits)` validates the
limits and the name (1–255 bytes, `NAME_MAX`, of `[A-Za-z0-9_-]`: every
cgroupfs interface file has a `.` in its name, so such a name can never
collide with one, nor be `.` or `..`), creates the directory, writes
`memory.oom.group`, `memory.swap.max`, `memory.max`, `pids.max`, `cpu.max`
and the `io.max` lines, and reads every one back (`Error::CgroupReadBack`
on a difference) before it returns, so before any process can enter
(`limits_written_before_entry` reads them from the host before the spawn).
On any error the directory is removed again. `Spec` takes `cgroup:
&Cgroup`, and `clone3` places the child with `CLONE_INTO_CGROUP` (the
constant is local: libc 0.2.191 has it only for glibc, as an overflowing
`c_int`), so the workload never runs outside its limits, not even for its
setup steps. `std::process::Command` could only move it after the fork
(D4, alternatives).

**The cgroup namespace after placement.** The child creates it with
`unshare(CLONE_NEWCGROUP)` as its first step after the id maps (D7), by
when `CLONE_INTO_CGROUP` has placed it, so the namespace is rooted at the
sandbox's cgroup: inside, `/proc/self/cgroup` is `0::/` and the cgroup2
mount shows the sandbox's own limits
(`cgroup_namespace_root_is_sandbox_cgroup`; without `CLONE_INTO_CGROUP`
the child stays in the runner's cgroup and both differ, measured with a
mutant that drops it).
**Measured against the plan, and the kernel code behind it:** D7 assumed
that a cgroup namespace created by `clone3` itself would be rooted at the
runner's cgroup, because `copy_process` creates namespaces before the move
into the target cgroup. The plan's mutant M13 (`CLONE_NEWCGROUP` in the
`clone3` flags, the `unshare` step removed) left the namespace rooted at
the sandbox's cgroup, and `cgroup_namespace_root_is_sandbox_cgroup` stayed
green (Linux 7.2.10). The reason is in `cgroup_post_fork()`
(`kernel/cgroup/cgroup.c`): when `CLONE_NEWCGROUP` comes with the clone,
it makes the target css_set (`kargs->cset`, the `CLONE_INTO_CGROUP`
cgroup chosen in `cgroup_css_set_fork`) the `root_cset` of the new
namespace before the child first runs. The block came with commit
ef2c41cf38a7 ("clone3: allow spawning processes into cgroups"), the
commit that introduced `CLONE_INTO_CGROUP`, in Linux 5.7; it is absent in
5.6 and present in 5.7, 5.19 and 7.0 (review of PR 3, from the kernel
sources). On every kernel the runtime accepts (5.19 floor), M13 is
therefore an **equivalent mutant**: no test can tell the two orders apart,
because they behave the same. The separate `unshare` step stays (one
syscall, the simpler reading). What matters is covered: a child that is
not placed at the clone (mutant C1) and limits written after entry (M12)
both fail tests, and `spawn_clone_flags` checks the exact flags that
`launch` passes to `clone3`, computed in one function (`clone_flags`), so
a flag added there fails it.

**`Mount::Cgroup2 { target }`**, always read-only, `nosuid,nodev,noexec`
(`Step::Cgroup2`): a cgroup2 mount in the sandbox's cgroup namespace,
rooted at its own cgroup. The sandbox's cgroup files belong to the host
user the inside id maps to (the runner created them), so a writable view
would let the sandbox raise its own limits; through the read-only mount,
writing `memory.max`, `pids.max` or `cgroup.kill` gives EROFS for inside
ids 0 and 999 (`sandbox_cannot_touch_own_limits`). A read-only cgroup2
mount works in a user namespace (measured). Until PR 4 drops the
capabilities (D9), inside id 0 can mount a writable cgroup2 of its own,
and can remount the `Mount::Cgroup2` view read-write (it lives in the
sandbox's own mount namespace, so no flag is locked; review of PR 3,
measured). Two kernel-enforced layers sit under the read-only view, both
added in the review round of PR 3:

- **`nsdelegate` is required** (`Features::probe`, id
  `cgroup-nsdelegate`, failing closed like every other host gap). The
  sandbox's limit files belong to the host user the inside id maps to,
  so file permissions admit a write; the only kernel check that refuses
  it is `cgroup_file_write()`'s refusal of non-delegatable files at a
  cgroup namespace root, which applies only when the hierarchy is mounted
  with `nsdelegate` (EPERM through a writable mount, measured on the dev
  host). `nsdelegate` is a superblock option only the initial namespace
  can set; systemd sets it. Without it a sandbox that regains
  `CAP_SYS_ADMIN` in any user namespace could raise its own
  `memory.max`, `pids.max` and `cpu.max`. Both CI runners mount cgroup2 with `nsdelegate`
  (printed by the "Host features" step, and the probe passes in the
  delegated scope), so the stock-runner expectation and the host-setup
  block stay as they are; a host without it is refused with
  `cgroup-nsdelegate`, and only root can fix it (remount with
  `nsdelegate`). The library checks it itself as well: `Parent::open` and
  `Parent::vacate_and_delegate` read `/proc/self/mountinfo` and fail with
  `Error::NsdelegateMissing` before they touch anything, so a runner that
  skips `Features::require`, or a host remounted after the probe ran,
  still gets no parent (re-review of PR 3; `parent_requires_nsdelegate`).
- **No sub-cgroups:** `Cgroup::create` writes `cgroup.max.descendants`
  and `cgroup.max.depth` 0 and reads them back. `nsdelegate` does not stop
  `mkdir` (delegation is its purpose), and a sub-cgroup the sandbox made
  kept `destroy` from removing the cgroup (EBUSY, review of PR 3). With
  both at 0, `mkdir` inside fails with EAGAIN, and raising
  `cgroup.max.descendants` from inside fails with EPERM, because it is not
  a delegatable file (`sandbox_cannot_create_sub_cgroups`, measured).

PR 4's capability drop then removes the mount and the remount
themselves.

**Destroying.** `Cgroup::destroy` writes `cgroup.kill` (Linux 5.14,
below the floor of D3), then lifts the throttles that can hold a killed
task back, then waits until `cgroup.events` says `populated 0`, and
removes the directory. The lift (review of PR 3): a task in one large
`O_DIRECT` write waits uninterruptibly for its queued bios, so
`cgroup.kill` cannot end it before they drain at the throttled rate. With
`wbps` 1 MiB/s and a 40 MiB write that is about 40 s, past the 10 s
bound, so `destroy` failed and left the cgroup; the workload picks that
time (size ÷ rate). After the kill, every configured `io.max` device is
written back to `max` (`destroy_lifts_io_throttle`: 89 ms on the dev
host; the reviewer measured 97 ms). A small CPU quota also holds killed
tasks back until the next period refill: with `cpu.max` `1000 1000000`
and four spinners, `destroy` took 496–506 ms without a lift (measured
three times), so `cpu.max` is written to `max <period>` as well
(`destroy_lifts_cpu_throttle`: 4 ms). Lifting after the kill is safe: a
killed task never returns to user space, so it can only finish what is
already in the kernel. Memory and task limits do not delay an exit. The wait polls `cgroup.events` for `POLLPRI`
and re-reads it at least every 100 ms in case a notification is missed;
10 s is a hang bound, not a target (`destroy_kills_all_and_removes`
measured about 3 ms for three sleepers). A killed child that its `Child`
has not reaped yet does not keep the cgroup populated, and the directory
can be removed before the reap (measured).

**Teardown never stops halfway** (re-review of PR 3). The kill, each lift,
the wait and the `rmdir` are each attempted even when an earlier one
failed, and every failure is collected into `Error::CgroupTeardown { path,
removed, errors }`. Before this, a failed lift returned early and skipped
the wait and the removal: a `Cgroup::create` whose `io.max` line the
kernel refused (ENODEV for an unknown device or a partition) had its
`Drop` write the same line again in the lift, fail, and leave the
directory behind. Two changes close that: a device is recorded for the
lift only after its `io.max` write succeeded (`refused_io_line_is_not_lifted`),
and a failed lift no longer skips anything (`teardown_continues_after_a_failed_lift`;
`failed_create_removes_its_cgroup` is the reviewer's repro: the directory
is gone and nothing is listed as leaked). `destroy` returns the error with
the path; a cgroup it could not remove is also recorded for
`leaked_cgroups()` (`destroy_failure_is_recorded_with_path`). Dropping a
`Cgroup` without `destroy` does the same work, but a drop cannot return
an error, and a panic there would abort a process that is already
unwinding; so a failed drop writes the error to stderr (the runner's
journal; the crate has no logger, and `tracing` is on the do-not-use
list) and records a directory it could not remove for `leaked_cgroups()`,
which the runner (#8) can report and #33's sweep cleans up
(`drop_reports_a_cgroup_it_cannot_remove`). A test failure or an early
return therefore leaves nothing behind unnoticed; a spawn that fails at a step leaves an empty,
removable cgroup (`failed_spawn_leaves_no_cgroup_process`, for an exec and
a mount failure). Cleanup after a runner crash is #33.

**Device mapping** (`block_device_of(path)`, for `IoMax::dev`): the
file's `st_dev` if `/sys/dev/block/<major>:<minor>` exists; otherwise
(btrfs and other file systems with anonymous device numbers; the dev
host's target directory has `0:43`) the source of the path's mount in
`/proc/self/mountinfo`, decoded from the kernel's octal escapes (`\040`,
`\011`, `\012`, `\134`) and parsed as bytes, because a mount path may hold
any byte but NUL, and its `st_rdev` if it is a block device node. A
partition maps to its disk through sysfs (its `partition` file, then the
parent's `dev`). Anything else, tmpfs or overlay, is
`Error::NoBlockDevice`. A btrfs file system that spans more than one
device fails closed with `Error::MultiDeviceFilesystem` (review of PR 3):
its mountinfo source names one member only (`btrfs_show_devname` prints
the latest device), so one `io.max` line would leave writes to the other
members unthrottled. The count comes from `BTRFS_IOC_FS_INFO`
(`num_devices`); an unreadable count fails closed too
(`multi_device_btrfs_rejected`, on fixture data; no multi-device btrfs
was available to measure). Other multi-device file systems do not reach
here: a ZFS or bcachefs source is not a device node, so they are
`NoBlockDevice`. The mount is found by its id (`statx` with
`STATX_MNT_ID`, Linux 5.8), not by `st_dev`, because a nested btrfs
subvolume has an `st_dev` that no mountinfo line carries. On the dev host
the target directory maps to `252:0` (the dm-crypt device), on which
`io.max` throttles (`io_limit_throttles_writes`).
`mountinfo_and_device_mapping` pins the decoding (exact for the four
escapes, `decode(encode(x)) = x` for every byte 0x01–0xff, malformed
escapes kept), partition to disk, the btrfs and nested-subvolume cases and
tmpfs, on fixture text.

**The timing tests** and their margins:

- `cpu_limit_throttles`: `cpu.max` `50000 100000` (half a CPU); the
  probe spins for 1.0 s of wall time and reads its own `cpu.stat` through
  the cgroup2 mount before and after: `usage_usec` ≤ 650,000 and
  `nr_throttled` ≥ 1. 650,000 = 500,000 (0.5 × 1 s) + 100,000 (the window
  can straddle one period refill) + 50,000 accounting slack; there is no
  lower bound, because a loaded host may give less. It spins on four
  threads, not one (the plan had one): on the loaded dev host a single
  spinner got 0.3 CPU, stayed under the quota and was never throttled
  (`usage_usec` 301,331, `nr_throttled` 0, measured), and QA saw two
  threads starve in 2 of 5 runs under other sessions' load
  (`usage_usec` 393,561 and 402,326, `nr_throttled` 0). More threads
  demand more CPUs, and the quota caps the whole cgroup, so the bound
  holds for any thread count. A run with `nr_throttled` 0 and
  `usage_usec` below 500,000 never reached the quota, so it says nothing
  about the limit: it is retried, up to 3 attempts, and three starved
  attempts fail with "host starved the probe", never pass. Any other run
  decides (`cpu_verdicts`: over 650,000 fails, at least the quota without
  a throttle fails). Under load on the dev host (three checksum loops in
  the same 300 % scope) 10 runs of 10 passed, two of them after one
  starved attempt (`usage_usec` 317,147 and 349,708, then 405,012 and
  475,653); passing values 372,160–508,292, `nr_throttled` 1–10.
- `io_limit_throttles_writes`: `io.max` `wbps=4194304` on the device
  behind the sandbox's `/workspace`; the probe writes 8 MiB with
  `O_DIRECT` (else `fdatasync` after every MiB): elapsed ≥ 1.5 s and
  `wbytes` ≥ 8,388,608. 8 MiB ÷ 4 MiB/s = 2.0 s; one 100 ms throttle
  slice (0.4 MiB) may pass early, leaving 1.9 s; 1.5 s leaves 0.4 s for
  timer granularity. The data is incompressible (xorshift), not zeros: the
  dev host's btrfs compresses, and 8 MiB of zeros reached the disk as
  299,008 bytes in 113 ms (measured). Dev host: 2011 ms, `wbytes`
  8,425,472. No block device fails the test with the reason.
- Both run alone: every sandbox run of the test binary holds a shared
  lock that the two take exclusively, so they do not compete with the
  other host tests for the CPU and the disk.

**The harness** gives every host test that does not set its own limits a
cgroup with `memory.max` 256 MiB without swap, `pids.max` 64 and
`cpu.max` `100000 100000` (one CPU), no IO limit: enough for the probe
(this test binary, a few MiB, and libtest) and the few children some
probes fork, small enough that a runaway probe cannot hurt the host, and
no swap so it cannot push the host into swapping.

**Where PR 3 departs from the plan of #6**, each for the reason given
above: `cpu_limit_throttles` spins on four threads and retries a run
the host starved (one spinner got 0.3 CPU on the loaded dev host and was
never throttled, measured), and the timing tests run alone; the IO probe writes incompressible data (zeros
reached the compressing btrfs as 299,008 of 8,388,608 bytes, measured); in
`memory_limit_kills_whole_group` PID 1 waits and its child touches (a dying
PID 1 takes its whole PID namespace with it); mutant M13 is not observable
on the dev host's kernel (measured; the order is still kept);
`IoLimits` refuses a zero rate (ERANGE, measured) and cgroup names are
limited to `[A-Za-z0-9_-]`; a parent with only pids reports `cpu`, the
first missing controller in the probe's order, where the plan's example
named `memory`; `block_device_of` finds the mount by its id and parses
mountinfo as bytes.

## Consequences

- `boneli-sys` depends on `libc` only (the edge `boneli-sys -> libc` is
  ADR-001's) and assembles the seccomp program itself; no new crate.
- The runtime needs Linux 5.19 and a host prepared for unprivileged user
  namespaces and cgroup delegation. Stock Ubuntu 23.10+ hosts need the
  AppArmor profile, and RHEL 9 and Ubuntu 22.04 GA are out.
- Every sandbox has a read-only root and the mounts its spec names, and
  nothing else of the host; callers pass canonical host paths, because
  every host path the child mounts — bind sources, layers and overlay
  directories — is resolved without following symlinks (D7).
- Every sandbox runs in a cgroup of its own with memory, swap, task, CPU
  and IO limits that are in place before it starts and that it cannot
  change from inside; the runner needs a delegated cgroup with the four
  controllers (D8).
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
