# ADR-044: Kernel floor Linux 6.1, checked through `pids.peak`

- Status: proposed
- Date: 2026-11-28

Amends ADR-007 D3 (the floor and how it is checked), the floor sentence of
ADR-019 D3 ("the sandbox needs Linux 5.19") and the first sentence of
ADR-043 D7 ("The floor stays Linux 5.19") together with its sentence on
the VM leg of #144, which runs the floor, now 6.1. Everything else in
those ADRs holds, the feature minimums included: Landlock ABI 2 and
`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` came with Linux 5.19, and that
stays what ADR-007 D3 and ADR-043 D7 say about them. ADR-009 D8 (`syncfs`
reports writeback errors since 5.8), ADR-028 and ADR-030
(`/proc/thread-self` since 3.17) name 5.19 only to show that a feature is
older than the floor; their argument holds at 6.1 unchanged.

## Context

ADR-007 D3 set the floor at Linux 5.19, the release that added Landlock
ABI 2 (`LANDLOCK_ACCESS_FS_REFER`), the newest feature the runtime uses.
The floor was the newest feature minimum, not a line anyone maintains.
Checked on 2026-11-28:

- **5.19 and 6.0 are end of life.** The last 5.19 release is 5.19.17
  (2022-10-24) and the last 6.0 release is 6.0.19 (2023-01-12), by the
  file dates of the cdn.kernel.org `v5.x/` and `v6.x/` listings; neither
  line is on kernel.org's longterm list.
- **6.1 is longterm.** kernel.org's `category/releases.html` lists 6.1 as
  released 2022-12-11 with a projected EOL of Dec 2027; its newest release
  is 6.1.193 (2026-11-23, `v6.x/` listing). 6.6 has the same projected
  EOL, 6.12 and 6.18 have Dec 2028, and 5.15 and 5.10 have Dec 2026 and
  are below the feature minimum anyway.

A floor upstream no longer fixes is a weak support statement, and #144,
the CI leg on the floor kernel, would test an image that gets no fixes.

**What distributions ship** (each row read on 2026-11-28 from the source
named; versions are the newest published package of the distribution's
default kernel):

| Distribution | Kernel | Source |
|---|---|---|
| Debian 11 / 12 / 13 | 5.10.223 / 6.1.176 / 6.12.117 | ftp-master madison, suites `oldoldstable` / `oldstable` / `stable` (bullseye 11.11, bookworm 12.15, trixie 13.8 by their `Release` files) |
| Ubuntu 22.04 | GA 5.15.0-204, HWE 6.8.0-149 | Launchpad published sources `linux` and `linux-hwe-6.8`, jammy |
| Ubuntu 24.04 | GA 6.8.0-151, HWE 6.17.0-42 and 7.0.0-44 | Launchpad, noble (`linux`, `linux-hwe-6.17`, `linux-hwe-7.0`) |
| Ubuntu 26.04 / 26.10 | 7.0.0-44 / 7.3.0-11 | Launchpad, resolute / stonking |
| Fedora 43, 44 | 7.3.6 | mdapi `f43-updates`, `f44-updates` |
| AlmaLinux and Rocky 9 / 10 | 5.14.0-741 / 6.12.0-264 | BaseOS package indexes of both |
| openSUSE Leap 15.6 / 16.0 | 6.4.0-150600 / 6.12.0-160000 | download.opensuse.org (`update/leap/15.6/sle`, `distribution/leap/16.0/repo/oss`) |
| Amazon Linux 2023 | `kernel` 6.1.190, `kernel6.12` 6.12.115, `kernel6.18` 6.18.62 | AL2023 core repository metadata (`primary.xml`, revision of 2026-11-27) |

Three points are assumptions, not checks: RHEL itself matches its
rebuilds AlmaLinux and Rocky, SLES 15 SP6 matches Leap 15.6 (Leap 15.6
builds the SLE 15 SP6 kernel, `150600` in its release), and SLES 15 SP7
does too. No kernel in the table lies in [5.19, 6.1), so a floor of 6.1
refuses no host that a vendor maintains and that 5.19 accepted.

**No interface the runtime calls changed from 5.19 to 6.1.** These files
are byte-identical in the `linux-5.19` and `linux-6.1` tarballs:
`kernel/seccomp.c`, `include/uapi/linux/{seccomp,sched,mount,openat2,pidfd,close_range,fcntl,keyctl,prctl,wait,ptrace,nsfs,signal}.h`,
`include/uapi/asm-generic/unistd.h` and
`arch/x86/entry/syscalls/syscall_64.tbl`; `landlock.h` and
`security/landlock/syscalls.c` differ only in kernel-doc markup, and 6.1
still reports Landlock ABI 2 (`LANDLOCK_ABI_VERSION 2`,
`security/landlock/syscalls.c:132`). So every probe of ADR-007 D3 and
ADR-043 D7 gives the same answer on 5.19.x, 6.0.x and 6.1.x, and the
floor can only be checked through something the runtime does not need.

## Decision

### D1. The floor is Linux 6.1

The rule: the floor is the oldest kernel.org longterm line that is still
maintained and not below the newest feature minimum (5.19). That is 6.1
(5.15 and 5.10 are maintained but below 5.19). What other values break:

- **5.19 (unchanged):** accepts two end-of-life lines, 5.19.x and 6.0.x,
  that no CI leg will run once #144 runs the floor.
- **6.6** has the same projected EOL as 6.1 (Dec 2027), so it buys no
  longer support horizon, and it refuses Debian 12 (6.1.176) and Amazon
  Linux 2023's default `kernel` (6.1.190).
- **6.12** (Dec 2028) refuses those two and also Ubuntu 22.04 HWE and
  24.04 GA (6.8) and Leap 15.6 / SLE 15 SP6 (6.4).

The feature minimums stay what they are: Landlock ABI 2 and
`WAIT_KILLABLE_RECV` came with 5.19, and the messages and comments that
name them say so; only the statements of the floor say 6.1. A new ADR
revisits the floor as 6.1's projected EOL (Dec 2027) nears.

### D2. Enforced by a marker: the pids controller's `pids.peak`

`Features::probe` refuses a kernel below 6.1 with the new id
`kernel-floor`. Since no interface the runtime uses changed (Context),
the check probes a 6.1 interface the runtime does not otherwise need, by
trying it, as D3 of ADR-007 requires (no `uname`: distributions
backport). The marker is `pids.peak`, a file of the pids controller that
Linux 6.1 added (commit 5251c6c436ed, in v6.1 and not in v6.0, checked
at both tags of torvalds/linux; `kernel/cgroup/pids.c:363` in 6.1, with
`.read_s64` and `CFTYPE_NOT_ON_ROOT` like `pids.max`), because:

- it needs no new kernel option: `CONFIG_CGROUP_PIDS` is required already,
  for the pids controller of ADR-007 D8;
- reading it needs no privilege and has no side effect;
- before 6.1 the answer is a deterministic ENOENT in a cgroup that has
  `pids.max`, so a refusal names a kernel age, not a host setting.

Rejected markers (each read in the 6.0 or 6.1 source):

- `STATX_DIOALIGN` (6.1): 6.0's `statx` refuses only `STATX__RESERVED`
  (`fs/stat.c:624` at v6.0), so an older kernel ignores the bit silently,
  and 6.1 sets it only where the file system reports it.
- `MADV_COLLAPSE` (6.1): accepted only with
  `CONFIG_TRANSPARENT_HUGEPAGE` (`mm/madvise.c:1167`–`1171` in 6.1), and
  the call collapses memory.
- `cgroup.pressure` and `irq.pressure` (6.1): they exist only with
  `CONFIG_PSI`, which the runtime does not require.
- `FAN_MARK_IGNORE` (6.0): it would let 6.0 through.
- Landlock ABI 3 (6.2): it would refuse 6.1.
- `PR_GET_AUXV` (6.4): `prctl.h` is identical at 5.19 and 6.1.

Rejected alternatives: **a support statement only**, which keeps
accepting 5.19.x and 6.0.x silently, so a user on an end-of-life kernel
learns it from a bug, not from the probe; and **`uname`**, which ADR-007
D3's backport rule rejects (RHEL 9 reports 5.14 and carries
backports such as `pids.peak`, see the stated limit below).

Stated limit: the marker checks kernel age, not patch level. 6.1.0
passes, and so does a vendor kernel that backports `pids.peak`; that is
D3's backport rule applied to the floor. CentOS Stream 9 (the source of
RHEL 9.10, 5.14.0, read on its `main` branch) is such a kernel: it
carries `pids.peak` and Landlock ABI 6, but not `WAIT_KILLABLE_RECV`
(no such flag in its `uapi/linux/seccomp.h`, and `kernel/seccomp.c:1808`
refuses unknown flags with EINVAL), so RHEL 9 and its rebuilds stay
refused by `seccomp-notify` as before and the marker changes nothing
for them.

### D3. The check

In `probe_cgroup`, once the caller's cgroup directory is known (the `0::`
line of `/proc/self/cgroup`, `own_cgroup_dir`) and before the delegation
check, `kernel_floor` stats `pids.max` and reads `pids.peak`, and the
pure `classify_kernel_floor` decides:

| `pids.max` | `pids.peak` | Result |
|---|---|---|
| ENOENT | ENOENT | `Unseen`: the controller is not visible here |
| ENOENT | present | `probe-failed`, stage `pids.max` (no kernel has that) |
| ENOENT | another errno | `probe-failed`, stage `pids.peak` |
| another errno | not read | `probe-failed`, stage `pids.max` |
| present | ENOENT | `kernel-floor` with the cgroup path |
| present | another errno | `probe-failed`, stage `pids.peak` |
| present | 1 to 19 ASCII digits that fit an `i64`, then exactly one `\n` | `Met` |
| present | anything else | `probe-failed`, stage `pids.peak`, the first 32 bytes escaped |

`Met` requires exactly what `read_s64` writes for a value at or above 0:
`i64::MAX` has 19 digits, so 19 is the longest valid number and 20 bytes
the longest valid content; the echo of 32 bytes shows any such content
whole and bounds a message about a file that is not the kernel's. A sign,
a space, a second newline or a non-ASCII digit is not what the kernel
writes, so it fails closed rather than passing. An errno other than
ENOENT says nothing about the kernel (a permission, a broken mount), so
it is `probe-failed` naming the file, never `kernel-floor` (ADR-007 D3's
rule for a probe's own failures).

The floor result is pushed before the delegation check returns early, so
a host that is not delegated and also below 6.1 is told both. After the
controllers check, `floor_after_controllers` closes the one gap
`Unseen` leaves: a cgroup that lists `pids` in `cgroup.controllers` but
had no `pids.max` is `probe-failed` at stage `pids.max`; without `pids`
listed, `cgroup-controller-missing` reports it. So `Features::probe`
returns `Ok` only after `Met`. On the dev host (Linux 7.2) the check is
`Met` (`pids.peak` holds the run's peak, measured), and the host probe
test reports nothing missing there and on both CI legs (7.0); the stock
runner step keeps exactly `userns-apparmor,cgroup-not-delegated`.

### D4. Older kernels: the sweeps re-anchored on 6.1

ADR-007 D2's "Older kernels" swept 5.19, 6.12 and 7.0 against 7.2 for
capability-less `request_module` sites and by-name crypto users. 6.1 is
added the same way, from `linux-6.1.tar.xz` (SHA-256
`2ca1f170…03b25deb`, as kernel.org's `v6.x/sha256sums.asc` lists it).

**Calibration first.** The method (every call of the named functions in
the C sources, architectures other than x86 and arm64, `drivers/gpu`,
`tools`, `scripts`, `samples`, `Documentation` and `usr` left out,
comments and strings stripped, definitions dropped, and for the module
list the definitions in `kmod.h`, `module.h` and `kmod.c`) reproduces
ADR-007's published counts exactly before it is run on 6.1: 335, 327
and 326 `request_module` sites and 360, 411 and 305 crypto users for
5.19, 6.12 and 7.2.

| | 6.1 | 5.19 (ADR-007) |
|---|---|---|
| `request_module` sites | 337 | 335 |
| of them not in 7.2 | 54 | 53 |
| by-name crypto users | 375 | 360 |
| of them not in 7.2 | 182 | 174 |
| in none of 5.19, 6.12 and 7.2 | 4 + 2 | - |

"Not in 7.2" counts a site whose file and call text do not occur in 7.2,
as ADR-007 does (upper bounds). A 6.1 site whose file and call text
occur in 5.19 or 6.12 was classified there. That leaves six sites in no
swept tag, all unreachable on the grounds of ADR-007's groups:

- `drivers/platform/x86/simatic-ipc.c:87` (`register_platform_devices`,
  from `module_init`) and `drivers/leds/simple/simatic-ipc-leds-gpio.c:85`
  (a platform driver's probe): drivers and internal.
- `drivers/staging/media/deprecated/tm6000/tm6000-cards.c:1048` and
  `:1051` (`request_module_async`, queued from the USB probe): drivers and
  internal.
- `drivers/md/dm-verity-target.c:1277` (`verity_ctr`, a device-mapper
  table load behind `/dev/mapper/control` and `capable(CAP_SYS_ADMIN)`,
  `drivers/md/dm-ioctl.c:1957`): devices.
- `fs/cifs/misc.c:1092` (`cifs_alloc_hash`, reached from an SMB session
  of a cifs mount, which `may_mount` refuses inside): mounts and
  in-kernel servers.

So the 6.1 sweep finds no capability-less site that no row closes, and
no seccomp row changes. ADR-007's older-kernel findings are in 6.1 too,
each closed as before: bpfilter (`net/ipv4/bpfilter/sockopt.c:31`, the
bpfilter row, 5.19 to 6.7), `binfmt-` by file content (`fs/exec.c:1742`,
residual 4), the tc classifier by name (`net/sched/cls_api.c:157`,
residual 3), TCP-MD5 by fixed name (`net/ipv4/tcp.c:4418`, the TCP
signature row) and fs-verity by fixed name (`fs/verity/hash_algs.c:68`,
the file-system crypto row).

Because `kernel/seccomp.c` is identical at 5.19 and 6.1, every 5.19 line
ADR-043 cites holds for 6.1, and because the syscall tables are
identical, the census's `NotImplemented` reasons ("every release from
5.19 to 7.2") cover 6.1. The Docker comparison of ADR-007 D2 applies a
rule when its `minKernel` is at most the floor, now 6.1; the pinned
profile has one `minKernel` ("4.8"), so the derived Docker lists do not
change.

## Consequences

- Hosts on 5.19.x and 6.0.x, which ADR-007 accepted, are refused with
  `kernel-floor`. RHEL 9 is refused as before (`seccomp-notify`).
- `Missing` and `MissingId` have a 17th member, `KernelFloor`
  (`kernel-floor`); the crate is unreleased and pre-1.0.
- The probe reads two more files per run.
- Amazon Linux 2023 passes the floor but has glibc 2.34 (its core
  repository metadata, `glibc` 2.34-231), below the 2.35 of ADR-019 D3,
  so it builds from source (`docs/release.md`). The gap is older than this
  ADR: AL2023 shipped 6.1 under the 5.19 floor too. This ADR does not
  change the glibc floor.
- #144 runs its VM leg on a maintained 6.1 kernel, not on 5.19.
- Kernels between the five swept tags (5.19, 6.1, 6.12, 7.0, 7.2) and
  backports stay unenumerated (ADR-007 residual risk 5).

## Alternatives considered

- **Keep 5.19 as the floor**: see D1; it keeps two end-of-life lines.
- **Raise the floor but only state it** (no probe): see D2.
- **6.6 or 6.12**: see D1.
- **Another marker**: see D2's list.

## Accept when

#144's leg on a 6.1 kernel runs the boneli-sys host suite with nothing
missing, so the marker is seen on the floor kernel itself, not only in
its source.
