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

**AWS-hosted x86_64 runners (#52).** Some `ubuntu-26.04` x86_64 jobs land
on AWS-hosted machines (2 of the 22 x86_64 `sandbox` jobs before #52, read
from the job logs; every arm64 job ran on Azure). They run
`7.0.0-1016-aws` (image build 20261111.82.6), against `7.0.0-1019-azure`
(x86_64) and `7.0.0-1017-azure` (arm64) on Azure. Their workspace is ext4
on a device-mapper snapshot over NVMe whose queue reports `dma_alignment`
511 and `max_sectors_kb` 128 (Azure: 3 and 63, 256 on both). Every class
runs THP `madvise`, `vm.dirty_ratio` 20, `vm.dirty_background_ratio` 10
and Yama `ptrace_scope` 1; the x86_64 images ship uutils coreutils 0.10.0
as `dd`, the arm64 image GNU coreutils 9.4. On AWS the `dd oflag=direct`
that `destroy_lifts_io_throttle` used before #52 exited 0 after 152 ms
under `wbps` 1 MiB/s: its 40 MiB `O_DIRECT` write returned EINVAL, and
`dd` cleared `O_DIRECT` and wrote the 40 MiB through the page cache
(strace, outside any limit), so the call returned once the bytes were
cached. The probe's one 40 MiB write from a 4096-aligned buffer is
accepted on the same device and held by `io.max` (D8, "The timing tests");
that `dd`'s buffer missed the device's 512-byte DMA alignment is inferred
from the EINVAL and the queue limit, not checked. Whether `io.max`
throttles the writeback of such page-cache data on AWS was open here
(over 3 s the 40 MiB stayed under writeback with `wbytes` 0 on both
device lines); #54 measured that it does, on the device line
`block_device_of` picks (D8, "Buffered writes and the statistics
keeper", AWS). The CI step "Host features" prints these facts on every run.

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
there is no io, measured at planning) and on both CI legs (D5). A
`Parent` runs no thread; every sandbox cgroup runs its own statistics
keeper ("Buffered writes and the statistics keeper", below).

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
  ENODEV for a partition (measured at planning). A buffered write is
  limited at its writeback, not in `write(2)`: the call returns once the
  bytes are in the page cache, and `io.max` applies when the kernel writes
  them out (D5: `dd`'s fallback on AWS). `memory.max` bounds the data
  waiting there, dirty or under writeback, because those pages are charged
  to the sandbox and cannot be reclaimed before they are written, so a
  writer cannot finish S bytes before S − `memory.max` of them passed the
  limit. Measured through the sandbox on the dev host (kernel 7.2, btrfs):
  512 MiB written without `O_DIRECT` and without a sync into `memory.max`
  256 MiB under `wbps` 32 MiB/s took 8,724–9,819 ms for the write loop
  (7 runs), above the 7,500 ms that bound allows (256 MiB ÷ 32 MiB/s =
  8,000 ms, less 100 ms for one throttle slice that may pass early and
  400 ms for timer granularity), and 274 and 318 ms without `io.max`. On
  the 7.0 CI kernels the same writer is OOM-killed instead of slowed: in
  every run on Azure x86_64, Azure arm64 and AWS x86_64, and in a sweep on
  Azure arm64 and AWS within 102 ms at `memory.max` 256 MiB and within
  302–312 ms at 1 GiB with 1,280 MiB written, both under 32 MiB/s. Without
  `io.max` some sizes were killed too (256 MiB on Azure arm64, 1 GiB on
  AWS) and none at 2 GiB; with the host reading `memory.stat` every 50 ms
  nothing was killed on the Azure legs (the cause is stale memcg
statistics, "Buffered writes and the statistics keeper" below). Small cgroups
  on the dev host behave the same: `memory.max` 32 and 64 MiB under `wbps`
  4 MiB/s and a 64 MiB write were killed after 325 and 644 ms with
  `file_writeback` at about `memory.max`, and 32 MiB without `io.max` was
  not (measured in transient units at planning). So a sandbox with
  `io.max` that writes through the page cache faster than its device
  drains can be OOM-killed with nothing wrong in its workload, and #8
  sizes `memory.max` and `wbps` together. The runtime's answer is each
  sandbox's statistics keeper, which holds such a writer at `memory.max`
  64 MiB and above on every CI class, with and without `io.max`; the
  cause, AWS, the floor and the tests that pin it are in "Buffered
  writes and the statistics keeper" below (#54).
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
written back to `max` (`destroy_lifts_io_throttle`: 89 ms on the dev host
with `dd`, the reviewer measured 97 ms; with the probe's write since #52,
16–35 ms on the dev host and 16–243 ms on CI, over the runs listed in
"The timing tests").
A small CPU quota also holds killed
tasks back until the next period refill: with `cpu.max` `1000 1000000`
and four spinners, `destroy` took 496–506 ms without a lift (measured
three times), so `cpu.max` is written to `max <period>` as well
(`destroy_lifts_cpu_throttle`: 4 ms). Lifting after the kill is safe: a
killed task never returns to user space, so it can only finish what is
already in the kernel. Memory and task limits do not delay an exit.
What is already in the kernel reaches the disk without `io.max` after the
lift, on the device behind the sandbox's writable files, and it has two
parts (review of PR 53). First the page cache, the sandbox's dirty and
writeback pages: at most `memory.max` by the bound in the `io` bullet.
Second every direct-I/O write already submitted, which `memory.max` does
not bound: an `O_DIRECT` write's bios carry the caller's own buffer pages, so
one `write` or `writev` call from a small buffer queues up to the
kernel's per-call cap (`MAX_RW_COUNT`, 2,147,479,552 bytes with 4 KiB
pages, from the kernel source) while the cgroup's memory stays small.
Measured by the reviewer on the dev host outside the sandbox, in a
transient scope with `MemoryMax` 64 MiB, no swap and
`IOWriteBandwidthMax` 1 MiB/s, on a btrfs directory without copy-on-write
so the write was truly direct: one `O_DIRECT` `writev` of 1,024 iovecs
over the same 128 KiB buffer (128 MiB in one call). At 3 s the task was
in `D` inside the call, `memory.current` 3,796,992 with `file_dirty` and
`file_writeback` 0, and the device-mapper line of `io.stat` counted all
134,217,728 bytes (the throttled disk's line 2,883,584); 1 s after
`cgroup.kill` the task was still in `D` and the cgroup populated; after
the lift the rest drained in 64 ms. So about 125 MiB, twice `memory.max`,
passed without the limit. `destroy_lifts_io_throttle` is an instance too:
the roughly 38 MiB still queued at its kill are direct bios (`file_dirty`
and `file_writeback` 0 on CI). Derived, not measured: per destroy the
direct part can reach about 2 GiB per task inside such a call, times the
tasks `pids.max` allows, plus asynchronous I/O (`io_submit`, which the D2
policy does not deny; it denies `io_uring`). The release follows from the
order in `kill_and_remove` (`write_kill`, then `lift_throttles`, then
`wait_unpopulated`). The page-cache part after the lift was measured in
#54 (W2: `memory.max` 1 GiB, `wbps` 8 MiB/s, 512 MiB, `destroy` as soon
as the write loop ended, a backlog of 182-512 MiB): `destroy` returned
after 0.8-2.3 s on AWS, 1.6 s on Azure arm64, 1.0-5.5 s on Azure x86_64
and 0.10-0.19 s on the dev host. The slowest, 512 MiB in 5.5 s, is
about 93 MiB/s, so `KILL_BOUND` (10 s) covers about 930 MiB of backlog
at that rate (derived, not measured). #8 cannot bound the release with
`memory.max` alone.
Deleting or truncating the sandbox's files before the kill is an option
for the page-cache part; whether it shortens queued direct I/O is not
checked.
**The limits are lifted only after the kill succeeded** (review round 3
of PR 3). Before, a failed `cgroup.kill` write was followed by the lift
anyway, so the surviving workload ran without its CPU limit (about
995,499 µs of CPU per second, the reviewer measured) in a cgroup that was
then left behind. Now a failed kill keeps every limit, skips the wait
(nothing would empty the cgroup), still tries the removal, and returns
`CgroupTeardown` with the cgroup recorded as left behind
(`failed_kill_keeps_limits`). **The kill cannot be blocked from inside:**
until PR 4 drops the capabilities, inside id 0 can mount a cgroup2 of its
own and `chmod 444` its `cgroup.kill`, and a write that opens the file by
name then fails with EACCES (measured). `create` therefore opens
`cgroup.kill` (write) and `cgroup.events` (read) once the limits are in
place and before any task can enter, and teardown uses those descriptors:
cgroupfs checks permission at open, not at each write, so a write through
the held descriptor still kills after the mode change (measured;
`kill_survives_chmod_from_inside`), and no `fchmodat` back is needed. The wait polls `cgroup.events` for `POLLPRI`
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
- `destroy_lifts_io_throttle` (#52): the probe makes one 41,943,040-byte
  `O_DIRECT` write under `wbps` 1 MiB/s from a buffer of its own
  anonymous mapping, advised `MADV_NOHUGEPAGE` before any byte is touched
  (review round 2 of PR 53). With transparent huge pages the buffer's
  pages are physically contiguous, the bios as large as the huge pages,
  and blk-throttle charges a bio whole before it splits it, so the first
  bio is dispatched only about its size ÷ `wbps` after the writer enters
  its write. Measured by the reviewer on the dev host, true direct I/O on
  a btrfs directory without copy-on-write, a 40 MiB write from a buffer
  forced to huge pages: the device's `io.stat` line read no write at 2 s
  and at 5 s while the writer sat in `D` inside the call, and counted
  15,642,624 bytes at once at 15.6 s; with `MADV_NOHUGEPAGE` 2,097,152 at
  2 s. Every class measured so far runs THP `madvise`, where an unadvised
  buffer gets no huge pages either; under THP `always` the held writer
  would have read as not on the device. The advice comes from a mapping
  of the probe's own because the allocator writes its chunk header next
  to the buffer, which under `always` can fault a huge page in before the
  advice; a kernel without THP answers `EINVAL`, which the probe accepts.
  From 2 s
  after the spawn on, every 100 ms (one throttle slice), the test reads
  `wbytes` on the `io.max` device's `io.stat` line and then the writer's
  own files: the cgroup must be populated, a task of the writer inside
  `write(2)` with that count (`/proc/<pid>/task/<tid>/syscall`), and its
  `wchar` under the count (`/proc/<pid>/io` adds a write only when it
  returns); `wbytes` must be above 0, so a limit on a device the bios do
  not pass cannot read as held behind a slow device (review of PR 53; a
  lower bound only, see below). Two cases make it read again, up to 10 s
  after the spawn: `wbytes` 0, and no task seen inside the write with
  `wchar` under 512 (#54). 512 because an `O_DIRECT` write returns only
  multiples of the logical block size, at least 512 bytes on every Linux
  block device, while the probe writes 38 bytes before its write
  (measured on every CI class and the dev host), so `wchar` under 512
  means that nothing of the write has returned yet. That is what the
  read shows, not that the writer is outside the write: the `syscall`
  file reads `running` for any runnable task, one inside the write
  included, and a failed write adds nothing to `wchar`. Waiting is right
  in each case: the next reads find the writer held, gone or still
  without a count at the deadline. A read that finds the writer gone,
  its write returned, or no task inside the write after a part of it
  returned (`wchar` from 512 up to the count) ends the wait with that
  verdict, so Held means the writer was inside its write after the
  device counted (review round 2 of PR 53). The report line lists the
  reads of the wait in order, as runs of one verdict with their count
  and the time of their first read, and names what ended the wait: a
  verdict, or the deadline. The entry wait comes from a failure in the
  QA of PR 58: with the dev host at a load average of about 19, the
  first read at 2,014 ms found the main thread in `futex` and the writer
  task `running`, `wchar` 38 and nothing counted, and the single read
  failed the test as not in the write; it passed 3/3 alone. The deadline
  covers an entry up to 10,000 − 1,000 (one 1 MiB bio at 1 MiB/s) − 100
  (one slice) = 8,900 ms after the spawn; a later entry only leaves more
  queued at the deadline, so the proof of the lift below is unchanged. A
  writer seen in its write without a count only from after 8,900 ms
  still fails at the deadline, and the message names the late start
  instead of a device the bios may not pass (review of PR 76). The
  fallback does not wait: without `wchar` it cannot tell a writer that
  has not entered from one that left, so a task in no `D` state stays
  final; it has decided on no CI class (D5). Then `destroy` must end the
  writer by SIGKILL within 5 s. A held write needs at least
  (41,943,040 − 104,858) ÷ 1,048,576 ≈ 39.9 s (one 100 ms slice may pass
  early).
  **Why a wait, and why 10 s.** The device counts a bio when blk-throttle
  dispatches it, the first one about (its size − 104,858) ÷ 1 MiB/s after
  the writer enters its write plus up to one slice of rounding, so at
  most its size ÷ `wbps`. With the advised buffer the first bio is 1 MiB
  (the reviewer's direct write counted 1,048,576 bytes at its first
  count, and CI read 1,048,576 at 2 s on every class), so the count comes
  up to 1.0 s after the entry; the dev host measured
  entries up to 872 ms after the spawn, which puts it at 1.87 s, 0.13 s
  before the single read at 2 s that the test made before. The reviewer
  measured a writer that entered at about 1.2 s: `wbytes` 0 at 2,007 ms,
  first count at 2,528 ms. Through the sandbox, with the probe delayed
  1.2 s before its write (a mutation copy, on a btrfs directory without
  copy-on-write so the write was truly direct), the single read at 2 s
  read `NotOnDevice` at 2,005 ms (1 run) and the wait read Held at 2,519
  and 2,520 ms, at its sixth read (2 runs). The upper limit is the proof
  of the lift: t seconds after the spawn at most (t + 0.1) MiB have
  drained, so 40 − (t + 0.1) MiB are still queued, and that must be more
  than `KILL_BOUND` (10 s) × 1 MiB/s = 10 MiB, or a destroy without the
  lift could drain inside `KILL_BOUND` and pass (mutant MA): t ≤ 29.9 s.
  10 s sits between the two: at 10 s at least 31,352,423 bytes (29.9 MiB)
  are queued, three times what the proof needs, and the count may come
  up to 10 s after an entry at the spawn, or the first bio may be up to
  about 9 MiB at the latest entry measured. A host whose first bio is
  larger fails, it never passes: huge-page buffers (forced in the same
  mutation copy with `MADV_HUGEPAGE`: `AnonHugePages` 40,960 kB, no
  count by 10,035 ms, the 80th read, "the io.max device counted no write
  within 10000 ms of the spawn") or, derived and not measured, a kernel
  with 64 KiB pages, whose 256-segment bios reach 16 MiB. The wait costs
  up to 10 s in that failure and about half a second on a late entry
  (the delayed-start runs above, Held at their sixth read); every other
  run measured with the wait, on both CI legs and the dev host, ends at
  its first read. `io_hold_deadline_keeps_the_lift_proven` pins the
  arithmetic, and the report line names the read count and the buffer's
  mapping in `/proc/<pid>/smaps` at the write's address (`nh` for the
  advice, and `AnonHugePages`). Measured through the sandbox: on the dev
  host the writer entered its write 263–872 ms after the spawn and read
  `wchar` 38 at 2 s, Held at 2,005–2,007 ms with `wbytes` 1,048,576 to
  1,572,864 and destroy 20–35 ms over 7 runs: 20–26 ms on the first tree
  of PR 53 (3 runs), 22 and 35 ms on its 17ce203, 22 and 24 ms on the
  tree of its first review round. On the trees of its second review
  round Held at the first read, 2,003–2,005 ms, destroy 20–27 ms (8
  runs; the 4 that looked the buffer up by the write's address read
  `40960 kB nh AnonHugePages 0 kB`), and in the mutation copy on the
  directory without copy-on-write 16–19 ms (3 Held runs, `wbytes`
  1,048,576 and `file_writeback` 0, as on CI). On CI, in the nine runs
  of PR 53's `sandbox` jobs up to its first review round's last commit
  ab19577 (runs 43757751313, 43758791004, 43759283155, 43759605908,
  43769894075, 43770174212, 43772627813, 43773252632 and 43773572845),
  Held at 2,001–2,002 ms with `wbytes` 1,048,576 on every class, destroy
  in run order 213, 211, 213, 225, 216 and 201 ms on Azure x86_64 with
  an NVMe disk (`259:0`, 6 runs; the third run's x86_64 job landed on
  AWS), 16 and 243 ms on Azure x86_64 with a SCSI disk (`8:0`, the same
  7.0 kernel, both runs on ab19577), 147, 131, 124, 125, 154, 126, 123,
  150 and 124 ms on Azure arm64 (9 runs) and 16 ms on AWS x86_64 (1
  run). These ranges cover the runs listed, not every runner class.
  Without the limit the writer had exited 0 by 2 s (dev host, 4 runs
  before the review and 1 in its first round) and the test fails with
  "io.max did not hold the writer". Where the runner refuses those files
  (EACCES, EPERM), a task in `D` decides and the report line says
  `hold-check=d-state`; `D` also shows a writer asleep elsewhere, for
  example in dirty-page throttling, so it is only the fallback. Every CI
  class so far has `ptrace_scope` 1 and read the files. `wbytes` has no
  upper bound: where `io.stat` counts depends on the write path, and
  some lines count above the rate (measured: the dev host counted a
  direct write that btrfs served through the page cache at its full 8
  MiB within 0.5 s under 4 MiB/s; in the reviewer's `writev` repro under
  "Destroying" the device-mapper line counted 134,217,728 bytes at 3 s
  under 1 MiB/s while the throttled disk's line read 2,883,584), so a
  bound tied to the rate could fail a held writer. Every class measured
  so far read 1,048,576 to 1,572,864 here, so the lower bound passes on
  all of them.
- They run alone: every sandbox run of the test binary holds a shared lock
  that the timing tests take exclusively, so they do not compete with the
  other host tests for the CPU and the disk.

**Buffered writes and the statistics keeper (#54).** Added by #54's
second PR; the measurements are in its pull request (#78), from
temporary diagnostic CI jobs on 16 x86_64 and 2-4 arm64 copies per round
and dev-host runs in a delegated scope. CI classes: AWS x86_64
`7.0.0-1016-aws` (workspace on the dm snapshot 252:0), Azure arm64
`7.0.0-1017-azure` (8:0), Azure x86_64 `7.0.0-1019-azure` and
`7.0.0-1020-azure` (workspace on `/dev/sda1`, 8:0, or on an NVMe device,
259:0); every class 4 vCPU and about 16 GB. Dev host: Linux 7.2.10.
"Source" below means upstream tags v7.0 / v7.2 (mm/memcontrol.c unless
named), read at planning; the CI kernels are Ubuntu builds of 7.0, so
every behavior claim comes from runs, and the line numbers locate the
code.

- **The problem.** A writer that writes through the page cache faster
  than the device drains it (`Limits` above) fills `memory.max` with
  dirty pages, which reclaim cannot free, and the cgroup is OOM-killed
  instead of slowed by dirty throttling (`balance_dirty_pages`,
  mm/page-writeback.c). With `memory.max` 256 MiB, `wbps` 32 MiB/s and
  512 MiB written, a host that only waits saw the writer killed in 53 of
  54 CI runs (M1, A0), and without `io.max` in 47 of 54 (N0).
- **H-S, stale memcg statistics.** The throttle stays out of the way
  while the memcg domain is under its freerun ceiling, (thresh +
  bg_thresh) ÷ 2 (page-writeback.c 813 in both; the check 1845 / 1847),
  and it takes the memcg's dirty count from `mem_cgroup_wb_stats`
  (3414-3437 / 3762-3785, called at page-writeback.c 860), which flushes
  the statistics only when the last flush is over 4 s old (3421 / 3769;
  635-639 / 740-744); the periodic flush runs every 2 s (`FLUSH_TIME`,
  559 / 664; 642-650 / 747-755). The headroom comes from the live page
  counter (3432 / 3780), the dirty count from the last flush. A writer
  at the measured 3.1-6.3 GiB/s fills 256 MiB in 40-64 ms. Evidence
  (M1): reads every 50 ms of files that flush nothing (`memory.current`,
  `memory.events`, `io.stat`) left 54 of 54 runs killed (A1), reads of
  `memory.stat` of the sandbox (A2) or of its parent (A3) every 50 ms 0
  of 54 each. A `memory.stat` read flushes: `memory_stat_show` (4527 /
  4905) → `memcg_stat_format` (1481 / 1693) → `mem_cgroup_flush_stats`
  (1495 / 1707), unratelimited, when more than 64 × online CPUs updates
  are pending (`MEMCG_CHARGE_BATCH`, include/linux/memcontrol.h 332 /
  331; 561-565 and 606 / 666-670 and 711): 256 on the runners, 768 on a
  12-thread host. A read at offset 0 of a held descriptor runs the show
  again (fs/seq_file.c 189 in both), so one descriptor serves every read.
  Tracefs on A0 showed the sandbox's first `balance_dirty_pages` after
  `oom:mark_victim` in every killed run. That a read flushes is kernel
  behavior, not documented API.
- **H4, a flushable sandbox stops the parent's read.** A keeper that read
  the parent every 10 ms (one read flushes the whole subtree through
  `css_rstat_flush`, 612 / 717, kernel/cgroup/rstat.c 388-431 / 397-440)
  still lost: 7 of 162 CI runs killed in M2a, and in the traced round
  (run 44740298530, 16 x86_64 copies) 67 of 1,920 K10 runs, while the
  control without reads (K0) was killed in 92 of 96 and N10 (no `io.max`)
  in 3 of 160. In all 67 killed runs the read at the write's start
  flushed and every later read of the parent was skipped
  (`memcg_flush_stats` `needs_flush=0`), the parent's `file_dirty` stayed
  at 0.1-0.3 MiB while the sandbox's `memory.current` reached
  `memory.max`, and the writer entered `balance_dirty_pages` 63-250
  times before the kill without being throttled. Cause, from the source:
  `memcg_rstat_updated` (567-597 / 672-702) walks from the writer's
  memcg (578 / 683) towards the root and stops at the first level that
  is already flushable (586-587 / 691-692), on the stated assumption that
  the ancestors are then flushable too (581-585 / 686-690); updates reach
  a level's counter only in per-CPU batches of 64. `__mem_cgroup_flush_stats`
  (599-613 / 704-718) skips a target at or below the threshold (606-607 /
  711-712). Once the sandbox's counter is over 256 while the parent's is
  not, the sandbox's updates never count towards the parent again, and
  every read of the parent is a no-op until something flushes the
  sandbox itself. How the state starts is inferred, not traced: a flush
  resets each memcg's counter in its per-CPU callback (4162-4165 /
  4540-4543), one CPU after the other with the lock dropped between
  CPUs (rstat.c 413-430 / 422-439), while the writer keeps updating; a
  parent reset after the sandbox's last one leaves the sandbox ahead.
  The same code is in v7.2. Reading the sandbox's own `memory.stat`
  (KS10) was killed in 0 of 960 traced runs; AWS's one copy had 0 of 120
  K10 runs killed, too few to tell whether its class differs.
- **Why the sandbox's own read is robust** (source): the throttle uses the
  dirty count of the writer's memcg (`wb->memcg_css`) and live page
  counters, no parent statistic (`mem_cgroup_wb_stats`); the update walk
  starts at the writer's memcg, whose counter gets every update unless it
  is already flushable, and then its own read flushes (606-612 /
  711-717). H4 needs a flushable level below the cgroup that is read, and
  a sandbox has none: `cgroup.max.descendants` and `cgroup.max.depth` are
  0 ("No sub-cgroups" above, `sandbox_cannot_create_sub_cgroups`).
  Residual, inferred: a flush racing an update can leave one flush window
  uncounted, and the next 64 × CPUs + 1 updates (257 on the runners,
  about 1 MiB of 4 KiB pages) make the sandbox flushable again, so it
  does not persist.
- **The decision: one keeper per sandbox** (`src/keeper.rs`). The last
  step of `Cgroup::create` opens the cgroup's own `memory.stat` relative
  to its directory descriptor (`O_RDONLY | O_NOFOLLOW | O_CLOEXEC`, no
  path), reads it once and starts the thread `memcg-keeper`, which reads
  it every `STATS_KEEPER_PERIOD` on deadlines (`pread` from offset 0 into
  a 4 KiB stack buffer until 0, content discarded, nothing allocated per
  tick). A missed period is counted as late and the schedule re-anchors
  without a burst. A file that cannot be opened or read fails `create`
  with `Error::CgroupFile`, one that reads as empty with
  `Error::StatsKeeper { errno: EIO }`, and a failed spawn with
  `Error::Sys`; each drops the cgroup, so no sandbox runs without its
  keeper. `kill_and_remove` stops and joins it right after a successful
  `cgroup.kill`, before the lift, the wait and `unlinkat`; after a failed
  kill it runs until the drop. A later read error is sticky in
  `KeeperReport::failed` and ends the thread; the sandbox is not killed
  for it, because that would turn a possible OOM kill into a certain one,
  and #8 checks the report with each run's outcome (an OOM kill after a
  keeper failure is unverified). `Cgroup::stats_keeper()` reports the
  reads, late reads, the largest gap, the longest read, the thread's
  whole CPU time (wake-ups included) and the failure. A `Parent` runs no
  thread. The thread lives in `boneli-sys`, the only crate with `unsafe`
  (`pread`, `clock_gettime`); no port sees it.
- **The period, P\* = 5 ms, by rule R-S1** (fixed in #54's plan before the
  data). M3 (run 44746104468 on d999fa9, 16 x86_64 and 4 arm64 copies,
  3 of the x86_64 copies on AWS; dev host once) read the sandbox's own
  `memory.stat` at the write's start and then every T (KS_T) at three
  sizes with the same loop bound, (M, `wbps` = M ÷ 8 s, 2M written):
  (64 MiB, 8 MiB/s, 128 MiB), (128, 16, 256), (256, 32, 512), 20 runs
  per size and T per copy, a held run cut 1.5 s after the write's start.
  A size holds at T when KS_T had no OOM kill there in any CI or
  dev-host run, and P holds a size when it holds at T = 2P. Killed runs
  of the 400 CI runs per cell (the dev host 0 of 20 unless noted; K0: 40
  CI runs, 2 per copy):

  | size | KS10 | KS20 | KS50 | KS100 | K0 (no reads, CI) |
  |---|---|---|---|---|---|
  | 64 MiB | 0 | 200 | 398 (dev 0) | 389 (dev 1) | 40 of 40 |
  | 128 MiB | 0 | 2 (arm64) | 267 | 392 | 39 of 40 |
  | 256 MiB | 0 | 0 | 0 | 388 | 40 of 40 |

  So 5 ms (T = 10) holds all three sizes, 10 ms (T = 20) loses 64 MiB on
  four of six CI classes and 128 MiB on arm64, 25 ms holds only 256 MiB
  and 50 ms none: P\* = 5 ms, the floor F = 64 MiB (R-S1; R-S2's fallback
  to 128 MiB was not needed). R-S3 (5 ms must hold 256 MiB) and R-S4 (no
  kill without `io.max` at T = 2P\*: NS10, 256 MiB, 512 MiB, uncut, 0 of
  210 runs) pass. **The factor 2** covers a host whose buffered writes
  are up to twice as fast as the fastest CI class, or a keeper woken a
  whole period late (inferred, not measured on such a host). **The
  margin per size**, the largest T held divided by P\*: 64 MiB 10 ÷ 5 = 2,
  128 MiB 10 ÷ 5 = 2, 256 MiB 50 ÷ 5 = 10. The kill times of the lost
  cells (20-62 ms after the write's start at 64 MiB, 35-83 ms at
  128 MiB, 69-172 ms at 256 MiB) bound what a period can miss: at
  64 MiB a 20 ms gap already reaches the kill on the fastest classes.
- **The floor, 64 MiB, documented, not enforced.** It depends on the
  host's buffered write rate, which `boneli-sys` cannot know, so a
  constant in `Limits::validate` would be wrong on other hosts, and the
  operator rejected a sizing rule. Below 64 MiB nothing was measured, and
  #8 sizes each sandbox at F or more, with headroom for faster hosts.
- **R-S5, the read's duration.** The p99 wall time of one read with 32
  sandboxes, each with its own reader at 5 ms (CS32), was 17-77 µs on
  CI, against the bound P\* ÷ 10 = 500 µs (a tenth of the one period of
  margin the factor 2 buys). The dev host, in a CPU-capped slice whose
  quota stalls threads (one read took 75 ms), measured 154-208 µs and is
  reported only. **CPU**, each keeper thread's whole CPU time over its
  life at 5 ms (debug build, the test binaries' profile): per sandbox
  per second 2.5-10.6 ms at N = 1, 2.7-8.5 ms at N = 8 and 2.3-8.3 ms at
  N = 32 on CI, 73.5-265 ms per second for all 32 together (7-27 % of
  one CPU); dev host 14.8-16.8, 11.0-11.4 and 8.0-8.7 ms per sandbox,
  257-279 ms in total at N = 32. CPU per sandbox per second = CPU per
  read ÷ P\*: 11-53 µs per read on CI is 2.3-10.6 ms per second. It is
  reported, not bounded; the flush walks every possible CPU and its
  threshold scales with online CPUs, so the cost on hosts with more CPUs
  is derived, not measured. `keeper_cost_report` asserts CPU per read
  ≤ P\* ÷ 10 at N = 1 and 8.
- **What could still defeat it.** (1) A writer in a sub-cgroup: excluded
  today (`cgroup.max.descendants`/`depth` 0, `nsdelegate` refuses to
  raise them, pinned by `sandbox_cannot_create_sub_cgroups`); per-container
  sub-cgroups (#8) would need a keeper per leaf. (2) A foreign inode,
  written back under another cgroup: the throttle then uses that
  cgroup's count; the traces saw no foreign dirtying and one inode wb
  switch in 67 runs; not covered. (3) A kernel whose `memory.stat` read
  stops flushing: the permanent tests fail with `OomKilled` and a keeper
  report that shows reads; detection covers only the kernels CI runs,
  and a runner kernel change shows in "Host features". Then the keeper
  needs another flushing read or a flush-independent mechanism. (4) A
  starved keeper: `late` and `max_gap` show it, and #8 must not
  CPU-limit the runner's cgroup so hard that the keeper falls behind.
- **Alternatives weighed.** The parent read (H4: 67 traced kills at
  10 ms). The parent read plus a fallback that reads the sandboxes when
  `memory.current` grows while `file_dirty` stands still: it reacts a
  period late on a heuristic, and the sandbox read needs neither. One
  thread per parent walking the sandboxes: staleness grows with N and
  the slowest read (the dev host's parent reads already had a p99 of
  506-3,325 µs at N = 32). A `memory.high` band (M1: 2 % at 64 MiB was
  killed in 52 of 54 CI runs, 5 % crawled 45 s at 2 GiB on the dev
  host); a band with a floor; a sizing rule; `vm.dirty_*` sysctls;
  tmpfs-only workspaces (#8); accepting the kill; a read triggered by
  `memory.events`, which fires at `memory.max`, when 21-30 ms are left
  on the fastest classes.
- **AWS (W1).** Buffered writeback under `io.max` is throttled on AWS:
  `memory.max` 1 GiB, `wbps` 8 MiB/s, 64 MiB and `fdatasync` took
  8,003-8,004 ms (bound 7,500), with `wbytes` 67,108,864 on the line
  252:0 that `block_device_of` picks; the COW device 259:1 counts the
  same bytes. Bio size at dispatch 4,096 bytes on AWS, 2,097,152 on Azure.
- **The tests.** `io_limit_holds_buffered_writes` (256 MiB, 32 MiB/s,
  512 MiB), `io_limit_holds_buffered_writes_at_floor` (F, F ÷ 8 s, 2F)
  and `buffered_writes_without_io_max_are_not_killed` (256 MiB, no
  `io.max`, 512 MiB) run the probe's `never` writer (1 MiB writes of
  incompressible data, no sync in the loop, then `fdatasync`) and must be
  Held: no OOM kill and exit 0, dirty or writeback data at the loop's
  end, the loop at least (S − M) ÷ `wbps` − 500 ms = 7,500 ms and the
  whole write at least S ÷ `wbps` − 500 ms = 15,500 ms (one 100 ms
  throttle slice and 400 ms of timer slack), every byte on the `io.max`
  device, and at least max(1, ⌊loop ms ÷ (10 × P\*)⌋) keeper reads during
  the loop (150 for a 7,500 ms loop). Verdicts in precedence:
  `KeeperFailed`, `OomKilled`, `WriterFailed`, `NotBuffered`, `Escaped`,
  `OffDevice`, `KeeperIdle`, `Held`. `keeper_reads_its_own_sandbox`
  (each keeper holds exactly its own sandbox's `memory.stat`, none the
  parent's, none left after `destroy` or a drop),
  `keeper_runs_while_cgroup_lives` and `keeper_cost_report` pin the
  lifecycle and the cost; the unit tests pin the schedule, the report,
  a refused start and a sticky failure. Mutation runs are listed in the
  PR: MK1 (no keeper thread) and MK-P (the keeper reads the parent) on
  CI; MK-P's behavioral run takes n = ⌈ln 0.01 ÷ ln(1 − p)⌉ = 50 runs of
  the floor test on Azure x86_64, with p = 23/260, the kill rate of
  parent reads every 5 ms at 64 MiB there (M3, KP5), so it misses a
  kill with probability 1 % or less (R-S6).
- **For #8.** One keeper thread per sandbox, from `create` to the kill,
  at the CPU above. A Landlock ruleset applied to the runner must allow
  reading `memory.stat` below the parent at every `create`, or `create`
  fails closed. Below 64 MiB nothing is promised.

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
- The runner process runs one `memcg-keeper` thread per live sandbox,
  reading that sandbox's `memory.stat` every 5 ms, and a buffered writer
  is held, not OOM-killed, only at `memory.max` 64 MiB and above (D8,
  "Buffered writes and the statistics keeper").
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
