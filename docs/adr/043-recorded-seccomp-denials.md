# ADR-043: Recorded seccomp denials: errno rows answered by a supervisor in the runner

- Status: accepted (2026-11-28, with part 2 of #45)
- Date: 2026-11-28

Amends ADR-007 D2 (how the errno rows are answered, and the program's
instruction count) and D9 step 6 (`sendmsg` and `close` run under the
filter before `execve`). Everything else in ADR-007 holds.

## Context

The seccomp filter of ADR-007 D2 answers 21 of its 22 rows with an errno
and nothing records the denial. A replicated application that needs a
denied call (a keyring call, a socket family outside Unix, IPv4, IPv6 and
netlink, a netlink protocol other than `NETLINK_ROUTE`, `io_uring`, `bpf`,
...) fails with a plain errno, and the debugging agent can take that
failure for the bug under investigation. A false bug is the costliest
error Boneli can make (#45). Recording each denial makes the cause visible
in the run's report, and later policy changes can be argued from recorded
data instead of guesses.

Issue #45 asks for the record (`Child::denials()` in boneli-sys, with the
syscall, its decoded key arguments and the pid inside the sandbox), the
same errno with and without the record, no path that lets a notified call
run, a reply to every notification and a denied call, not a hung one,
when the supervisor stops or dies, and the minimum kernel of each feature
used. It leaves open which rows notify and what happens to the `clone3`
to ENOSYS fallback. #8 carries the record into the `Sandbox` port's
`ExecResult` and the run's record (requirement comment on #8, decided at
#45 STOP 1); this ADR ends at boneli-sys.

The work lands in two PRs under #45. PR 1 (this ADR, proposed) carries
the pure part: one return per row, the notifying program, the evaluator,
the record with its keys, decoding and rendering, the status parser and
the deny-only reply encoding, all tested in `check`; `spawn` still
installs the plain program. PR 2 carries the FFI, the listener hand-off,
the supervisor thread, the probe id, the host tests and the measurements
on CI, and accepts this ADR.

Measurements quoted below were taken on the dev host (Fedora 44, Linux
7.2.10 x86_64, glibc 2.43) while #45 was planned (2026-11-27), with a
throwaway C harness, unless they name a test of this crate. Kernel lines
cite `kernel/seccomp.c` at the `v5.19` and `v7.2` tags.

## Decision

### D1. Every errno row notifies; the kill row does not

| Row | Notifies | Why |
|---|---|---|
| ForeignArch | no | `SECCOMP_RET_KILL_PROCESS`. A notification can only end in an errno or in the call running, so notifying would turn a kill into an errno. The exit status (`Signaled(SIGSYS)`) is its record. |
| Ceiling, IoUring, BpfUserfaultfdPerf, Keyring, Syslog, NewUserNamespace, SocketFamily, SockPacket, NetlinkProtocol, InetProtocol, Socketpair, HugetlbMmap, HugetlbShmget, HugetlbMemfd, LineDiscipline, ModuleIoctl, Ktls, TcpSignature, Bpfilter, FsCryptoIoctl | yes | Each is a call the workload made and the sandbox refused. Each can make an application fail in a way that looks like its own bug, which is what #45 is about. |
| Clone3 | yes | See below. |

**Clone3 notifies.** glibc 2.34 and newer fall back to `clone` on ENOSYS,
so most `clone3` denials are noise. Measured with `clone3` notified and
answered ENOSYS:

| Workload | `clone3` notifications |
|---|---|
| 16 pthreads | 1 |
| 8 `posix_spawn` | 8 |
| 16 pthreads + 8 spawns | 9 |
| `node -e 0` | 1 |
| node Worker | 1 |
| node 8× `execFileSync` | 1 |
| Python 8× `subprocess.run` | 8 |
| Python 16 threads | 1 |
| GNU make 4.4.1, 4 recipe lines | 4 |
| `sh -c` | 0 |

So glibc caches the ENOSYS for threads but not for `posix_spawn`
(inferred from the counts). It is still recorded because `clone3`'s flags
sit behind a pointer the filter cannot read (ADR-007 D2), and a program
that calls `clone3` without a fallback (a static binary, a runtime with
its own syscall layer) otherwise fails with no trace. The record
aggregates by key (D6), so whatever the count, a run holds one Clone3
entry. Its rendering carries the note "libc falls back to clone, where the
NewUserNamespace row sees the flags", so the agent does not chase it. The
weak spot: that entry shows up in nearly every glibc run.

### D2. Two programs, one decision

The policy assembles two programs from one source (`Policy::program` and
`Policy::notifying_program`). They are the same instruction for
instruction except the 21 errno returns: `SECCOMP_RET_ERRNO | errno` in
the plain program, `SECCOMP_RET_USER_NOTIF` in the notifying one. The KILL
return and both ALLOW returns are the same. So which calls the notifying
program denies is the plain program's decision by construction, and
`notifying_program_differs_only_in_errno_returns` pins it for both
architectures.

**One return per row.** ADR-007 D2's program shared five errno returns
(EPERM, ENOSYS, EAFNOSUPPORT, EPROTONOSUPPORT, ENOPROTOOPT); here every
errno row has its own, so a return index names exactly one row
(`Program::row_at`) without a Rust copy of the policy. The program grows
from 88 to 104 instructions on both architectures: 88 − 5 shared returns
+ 21 row returns = 104 (`program_shape` pins it). The longest jump is
101 instructions on both architectures (measured), below the 8-bit limit
of 255. Every existing policy test of ADR-007
D2 runs unchanged against the new plain program and is green, which shows
that no decision moved.

**The errno comes from the plain program.** The supervisor evaluates the
plain program on the notification's `seccomp_data`
(`seccomp::bpf::evaluate`, safe code with no allocation, for the
assembler's subset only: `LD|W|ABS` at offsets 0 to 60 that are multiples
of 4, `JEQ`/`JGT`/`JSET` with a constant, `RET` with a constant) and
replies with the errno of the row whose return it reached
(`notify::decide`). Any other opcode, a load outside `seccomp_data`, a
jump past the end, running off the end or an empty program gives
`SECCOMP_RET_KILL_PROCESS` with no row (`evaluator_fails_closed`). The
evaluator and the test interpreter of ADR-007 D2, written independently,
agree on both programs for every number from 0 to 479, the ceiling forms,
three foreign architectures and every census form
(`evaluator_matches_interpreter`). A notification the plain program
allows or kills, whose return names no row, whose action is not the
row's errno, or whose arguments do not fit the row's key
(`Key::of` gives `None`) is inconsistent: the supervisor replies ENOSYS,
marks itself failed and stops (`answer_derivation`). Rejected: a Rust
table mirroring the policy's errnos, which could drift from the program.

### D3. The hand-off

The child installs the notifying program as the last step before
`execve` (ADR-007 D9 step 6) with `SECCOMP_FILTER_FLAG_NEW_LISTENER |
SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`. The kernel creates the listener
close-on-exec (`get_unused_fd_flags(O_CLOEXEC)`, 5.19 `:1876`, 7.2
`:1995`). The child sends it to the parent over a dedicated `socketpair`
(`AF_UNIX`, `SOCK_STREAM | SOCK_CLOEXEC`) as one byte with one
`SCM_RIGHTS` descriptor from a stack buffer, closes it, then runs
`execve`. So `sendmsg` and `close` are the two calls that run under the
filter before `execve`; neither is denied by any row. The parent reads the
message after the setup report succeeded with `MSG_DONTWAIT |
MSG_CMSG_CLOEXEC` and requires exactly one byte and one `SCM_RIGHTS`
message holding exactly one descriptor, without `MSG_CTRUNC`; anything
else is a protocol error (`ProtocolError::Listener`), and the child is
killed and reaped. The receive buffer has room for two descriptors, so a
message with two is seen as two, not cut to one, and every descriptor
that arrived is owned at once and closed on refusal. No message at all
(an empty socket, or its end once the child's copy closed at exec) is
`Missing`; so is a child that died before the hand-off, which used to
look like an exec with an exit code and now fails the spawn. The message
is queued before the report pipe's EOF because the child sends it before
`execve`. `Step::Listener` gets the new code 30 (the codes are wire
format, ADR-007 D4). `listener_hand_off_fails_closed` injects a failed
step, no message, a message without a descriptor, one with two and one
without its byte, and checks each is refused with the child reaped and
no descriptor left; `listener_is_close_on_exec_in_the_runner` checks the
runner's copy has `FD_CLOEXEC` and is gone after `wait`.

Why a separate socket: ADR-007 D4's 12-byte/EOF report protocol stays as
it is. Rejected: rewriting the report channel as `SOCK_SEQPACKET` (a
larger review surface for the same result), `pidfd_getfd` from the parent
(the child would have to wait for the parent before `execve`, and Yama
`ptrace_scope` 2 and 3 refuse it), and installing the filter from the
parent (seccomp applies only to the calling task).

### D4. The supervisor and fail-closed handling

One supervisor thread (`seccomp-notify`) per sandbox, in the process that
called `spawn` (the runner). It loops: `poll` on the listener and a stop
pipe, `SECCOMP_IOCTL_NOTIF_RECV` into a zeroed buffer (`ENOENT` or
`EINTR`: continue), `decide` (D2), note the call (D6), send the reply
(D5). Only for the first occurrence of a key whose pid is unknown does it
read `/proc/<pid>/status` and then check `SECCOMP_IOCTL_NOTIF_ID_VALID`,
so the status it read belongs to the caller; repeated keys skip `/proc`.
`ENOENT` on send (the caller is gone) counts as `unanswered`. Any other
error, an inconsistent evaluation or a panic sets `failed`
(`SupervisorFailure`), ends the loop and drops the listener. The loop
ends on `POLLHUP` (5.19 `:1759`: no task uses the filter any more) or on
stop. `Child::wait` reaps, then stops and joins the supervisor; `Drop`
kills, reaps, stops and joins. `spawn` returns only after the thread
has started, named itself and set its signal mask (a ready message from
the thread). The thread blocks every signal but the C library's own
(`sigfillset` + `pthread_sigmask`, which leave out glibc's 32 and 33 and
musl's 32 to 34), so a process-directed signal of the runner goes to
another thread and none of its waits is interrupted. The library's own
signals must stay open: `setuid`, `setgid` and `setgroups` send
`SIGSETXID` to every thread and wait for each handler, so a supervisor
that blocked it would hang them, every later thread start and its own
exit (found in review of PR 2, which blocked all 64 through the raw
syscall; `set_id_calls_run_while_a_sandbox_runs` hangs on that mask and
passes on this one). On every path that ends the loop with a failure the
supervisor records the failure before any call gets ENOSYS for it: the
inconsistent path records it before its own ENOSYS reply, and the stop,
panic and listener-error paths record it before they close the listener.
So a reader that sees a call answered ENOSYS finds the reason in the
record even while the sandbox runs (`panicked_supervisor_leaves_calls_denied`
and `inconsistent_notification_is_denied_and_fails` read it then); the
record is complete once `wait` returned.

**A lost supervisor leaves calls denied, not hung.** When the listener's
last descriptor closes (stop, panic, runner death), the kernel answers
every pending notification with ENOSYS (`seccomp_notify_detach`, 5.19
`:1413`, 7.2 `:1475`) and every later notified call with ENOSYS because
the filter has no listener (`err = -ENOSYS` before `if
(!match->notif)`, 5.19 `:1107`, 7.2 `:1174`). The calls fail; they never
run and never block. `Denials::failed` lets a caller treat a record that
stopped early as a failed run (#8).

**Why the runner and not the sandbox.** The workload shares the shim's
uid and user namespace, so where Yama allows it, a supervisor inside the
sandbox or in the shim could be reached with `pidfd_getfd` or ptrace, and
the workload could take the listener and let its own calls run.

**Wait-killable receive is on.** Once the supervisor has received a call,
a non-fatal signal no longer turns the denial into EINTR or a restart
(`should_sleep_killable`: `state == SENT` at 5.19 `:1093`, `state >=
SENT` at 7.2 `:1160`); a killing signal still ends the task. Its cost was
within noise: p50 8.6 to 10.2 µs per denied call with it, 8.4 to 9.9 µs
without (3 runs × 20,000 calls each). Before the receive, a signal still
interrupts (without `SA_RESTART`) or restarts the call; it is never
allowed. The interrupted task withdraws its notification before any
receive (`list_del` on the interrupted path of
`seccomp_do_user_notification`), so the call that fails with EINTR is
not in the record and a restarted call is counted once
(`signal_before_receive_restarts_or_interrupts`, which delays every
receive by 1 s and interrupts the call with a 100 ms timer). The plan of
#45 expected a restarted call to count twice; the host test showed it
counts once, and the record misses an interrupted one.

### D5. Deny-only replies

`notify::Deny::new(id, errno)` is the only constructor of a reply. It
accepts errno 1 to 511 and encodes `val` 0, `error` −errno and `flags`
0. Why that range. The kernel returns `error` when it is non-zero and `val` otherwise
(`syscall_set_return_value(..., err, ret)`, 5.19 `:1186`; on x86
`regs->ax = (long) error ?: val`, `arch/x86/include/asm/syscall.h:78`).
So `error` 0 makes the call return `val`, a success. At the other end,
512 and up are the kernel's own codes, which "should never be seen by
user programs" (`include/linux/errno.h`, 512 `ERESTARTSYS` to 531
`ENOGRACE` in 7.2): with a signal pending, `ERESTARTSYS`,
`ERESTARTNOINTR` and `ERESTARTNOHAND` make the kernel restart the call
instead of failing it, and `ERESTART_RESTARTBLOCK` (516) runs the task's
restart block, which is another syscall's continuation (found in review
of PR 1). So the bound is 511, one below `ERESTARTSYS`. It costs nothing:
the highest errno in the uapi headers of both architectures is
`EHWPOISON` (133, `include/uapi/asm-generic/errno.h`), and the rows use
five errnos up to 97. `MAX_ERRNO` (4095, `include/linux/err.h`), the
kernel's bound for a return value to be an error at all, would admit the
internal codes (`deny_reply_encoding` refuses 0, 512 to 531, 4095 and
4096). The kernel's send path itself bounds none of this (5.19
`seccomp_notify_send`, `:1525`–`1568`).

Nothing in boneli-sys can reply with the flag that lets a notified call
run, nor inject a descriptor (which with its send flag fakes a success).
The pin is a test plus structure, not an architecture-checker rule:
`no_continue_reply_in_boneli_sys` scans every file under boneli-sys `src/`
and `tests/` and fails on the names of the continue flag, the
descriptor-injection ioctl, its two flags and its struct, and the
flag-setting ioctl, in code, a comment or a string, after `libc::` or
renamed with `use ... as`. The send ioctl's name and the reply struct may
appear only in `src/seccomp/notify.rs`.

For numbers the scan reads every integer literal, in any base, hex case,
with `_` separators and a suffix, and folds it to its low 32 bits, because
`cmd` is an `unsigned int` and the kernel drops the rest; after a `-` or
`!` it also checks the negated and complemented value. The send ioctl's
32-bit number may then appear only in notify.rs: the kernel matches it
exactly. The injection ioctl is matched on its type and number bits only
(`'!'`, 3: the low 16 bits 0x2103), because the kernel dispatches it on
`EA_IOCTL(cmd)`, which masks the direction and size bits
(`seccomp_notify_ioctl`, `kernel/seccomp.c:1726` in 5.19, `:1846` in
7.2). So no literal anywhere may carry those 16 bits. The reviewer's C
probe on 7.2.10 reached the handler with every direction, with size 32,
with a 64-bit request whose low word is the ioctl's and with the send
number's 64-bit and negative spellings, and the first version of the scan
missed them (found in review of PR 1); each is now a fixture of
`continue_scan_catches_every_form`, with neighbours that must pass. What
the scan proves is therefore about literals: no integer literal in
boneli-sys, written alone or directly after one unary `-` or `!` (blanks
aside), is a request the kernel dispatches to the injection ioctl, or to
the send ioctl outside notify.rs. It does not read float literals and
does not look past a parenthesis, a comment or a second unary operator
between the operator and the literal (`-(N)`, `- /*c*/ N`, `-!N`,
`N as f64 as _`; found in review of PR 1); those are spellings someone
has to write on purpose, and they belong to the residual below.
Only boneli-sys can issue an ioctl (`unsafe` is allowed nowhere else,
rules `unsafe-token` and `lints-unsafe`), so one crate's sources are the
whole scope. Rust has no stable way to build an identifier without a proc
macro, which rule `proc-macro` bans, so a name has to be written to be
used. Residual: a number computed inside boneli-sys (through `ioc()`, a
shift, an `|` of two harmless literals, a constant expression, or one of
the deliberate literal spellings above) is caught
only by review; boneli-sys is always reviewed, and
PR 2's host tests show that no notified form succeeds. Rejected: a
checker rule, which would add a third always-review surface for the same
names.

### D6. The record

`Child::denials()` returns a snapshot (`Denials`): the entries in the
order their keys were first seen, the `unanswered` count and `failed`.
An entry (`Denial`) holds its row, its key, a count that saturates at
`u64::MAX` and the first occurrence in full: its sequence number among
all noted calls, the time since spawn, the raw syscall number and six
arguments, the errno, the pid inside the sandbox and the comm.

**Keys.** A key is a row and a selector: a value from that field's table
or "other". The key space is finite, so every denied call is counted in
some entry and none is dropped:

| Row | Keys | Rule |
|---|---|---|
| IoUring, BpfUserfaultfdPerf, Keyring, Syslog | 10 | by syscall number (3 + 3 + 3 + 1) |
| Ceiling | 41 | numbers 472 to 511 each, everything above (x32 numbers and −1 included) shares one |
| NewUserNamespace | 2 | by syscall (`clone`, `unshare`) |
| Clone3 | 1 | |
| SocketFamily | 43 | families 0 to 45 except 1, 2, 10 and 16, plus one for the rest |
| SockPacket | 1 | |
| NetlinkProtocol | 32 | protocols 1 to 31, plus one for the rest |
| InetProtocol | 520 | family {2, 10} × each denied protocol 0 to 262 (259 per family), plus one for the rest per family |
| Socketpair | 46 | families 0 to 45 except 1, plus one for the rest |
| HugetlbMmap, HugetlbShmget, HugetlbMemfd | 3 | |
| LineDiscipline | 1 | |
| ModuleIoctl | 8 | by `cmd` |
| FsCryptoIoctl | 3 | by `cmd` |
| Ktls | 1 | |
| TcpSignature | 3 | by `optname` |
| Bpfilter | 8 | (`setsockopt` or `getsockopt`) × `optname` 64 to 67 |

10 + 41 + 2 + 1 + 43 + 1 + 32 + 520 + 46 + 3 + 1 + 8 + 3 + 1 + 3 + 8 =
723 keys on each architecture (`key_space_is_bounded` enumerates the
rule, pins the total and sweeps every selector field to show that each
denied call's key is in the set). Where the table bounds come from: 46 is
`AF_MAX` in 7.2, and the kernel itself refuses higher families; 32 is
`MAX_LINKS`, above which `netlink_create` refuses; 262 is
`IPPROTO_MPTCP`, the highest IP protocol in the 7.2 uapi, above which
`inet_create` refuses with EINVAL. The ceiling window is 40 numbers: from
424 (Linux 5.1, 2019) to 471 (7.2) Linux added 48 numbers in about seven
years, so 40 cover about five to six years of new syscalls before they
share one key, and the raw number of the first stays in the entry. A key
is taken from the low word of each selector argument, as the filter reads
it; the raw 64-bit values stay in the first occurrence.

**Decoding.** `describe_call` names every selector value the rows test,
from tables pinned to `libc` at compile time where libc has the constant
and cited from the uapi header otherwise (libc 0.2.191 lacks `AF_SMC`,
`AF_MCTP`, and for gnu targets `AF_KCM`, `AF_QIPCRTR` and `AF_MAX`, the
`TLS_*` options and the bpfilter and ip6tables option names). Other
arguments print as numbers (ints signed, as the kernel reads them), and
flags print their named bits, the huge page size field (`MAP_HUGE_2MB`
for 21 << 26) and the unknown remainder in hex. Only the key arguments
are shown; descriptors and pointers are not. `Denial::render` gives one
ASCII line, for example `socket(domain=AF_VSOCK, type=SOCK_STREAM,
protocol=0) -> EAFNOSUPPORT, row SocketFamily, 8000 calls, first at
+0.012s, pid 17, comm "probe"` (`render_one_entry_per_row` holds the
golden line of each of the 21 rows). The record has no serialized form
here; #8 defines the event form.

**The pid.** The notification names the calling thread in the runner's
PID namespace. `parse_status(bytes, notif_pid)` reads
`/proc/<pid>/status`: it takes the last field of `NStgid:` (the thread
group id in the innermost namespace, what the caller's `getpid()`
returns) only when the file's `Pid:` field equals the notification's pid,
so a procfs that shows another namespace's process under that number
gives nothing. Only lines that end within the first 8,192 bytes count
(D8).

**The comm** names a process whose pid may be gone by the time anyone
reads the record. The kernel escapes only `\n` and `\` in the `Name:`
line (`proc_task_name`, `fs/proc/array.c`, `seq_escape_str(m, tcomm,
ESCAPE_SPACE | ESCAPE_SPECIAL, "\n\\")` in 5.19 and 7.2), so no comm can
move a line; the parser undoes those two escapes and refuses any other
escape or a comm longer than 15 bytes (`TASK_COMM_LEN` 16). Rendering
re-escapes everything outside printable ASCII, plus `\` and `"`, as
`\xHH` (`escape_comm`), so a workload cannot put a line break, a terminal
escape or a bidirectional override into the report
(`comm_rendering_escapes_hostile_bytes`).

**No workload memory is read.** Pointer arguments stay raw values.
Reading them would race the workload, as seccomp_unotify(2) warns, and
the call is denied anyway.

### D7. Minimum kernel per feature

The floor stays Linux 5.19 (ADR-007 D3). Read in the `linux-5.19`
source:

| Feature | In 5.19 |
|---|---|
| `SECCOMP_RET_USER_NOTIF`, `SECCOMP_FILTER_FLAG_NEW_LISTENER`, the listener created `O_CLOEXEC` | `kernel/seccomp.c:1876` |
| `SECCOMP_GET_NOTIF_SIZES` | `:1997` |
| `SECCOMP_IOCTL_NOTIF_ID_VALID`, both numbers | `:1720` |
| `EPOLLHUP` on a listener whose filter has no users | `:1759` |
| `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, accepted only with `NEW_LISTENER` | `:900`, `:1866` |
| ENOSYS with no listener, ENOSYS on detach | `:1107`, `:1413` |

`WAIT_KILLABLE_RECV` came with commit `c2aa2dfef243` ("seccomp: Add
wait_killable semantic to seccomp user notifier"), which v5.18 does not
contain and v5.19 does (checked against both tags). It is the newest
feature used, so the mechanism's minimum equals the floor; the others are
older and present in 5.19 at the lines above.

`Features::probe` has the id `seccomp-notify` (`NotifyGap`):
it is reported when installing an allow-all filter with both flags fails
(EINVAL: no `WAIT_KILLABLE_RECV`, a kernel below 5.19; EBUSY: the runner
already runs under a filter with a listener, `has_duplicate_listener`,
5.19 `:1807`/`:1904`), when `SECCOMP_GET_ACTION_AVAIL` refuses
`SECCOMP_RET_USER_NOTIF`, or when `SECCOMP_GET_NOTIF_SIZES` reports less
than the compiled sizes. The host tests run on both CI legs (7.0) and the
dev host (7.2); no CI or dev host runs 5.19, so differences between 5.19
and 7.x are read, not run, and #144 adds a 5.19 VM leg for all of
ADR-007. Example of such a difference: 5.19's `should_sleep_killable`
tests `state == SENT` where 7.2 tests `>= SENT`, so on 5.19 a reply that
races a signal restarts the call, which counts it twice but never allows
it.

The kernel's struct sizes are read at run time, not assumed:
`notify::Buffers::for_sizes` takes `SECCOMP_GET_NOTIF_SIZES` and gives
zeroed, 8-aligned receive and reply buffers of the kernel's size (the
kernel requires a zeroed receive buffer, `check_zeroed_user`, 5.19
`:1462`), at least this crate's 80, 24 and 64 bytes, and
`Error::NotifySizes` when the kernel's are smaller. A newer kernel's
larger structs work: the crate reads and writes only its own prefix
(`notif_buffers_follow_kernel_sizes`).

### D8. The numbers

| Number | Value | Where it comes from, and what breaks at another value |
|---|---|---|
| Program length | 104 | 88 (ADR-007 D2) − 5 shared returns + 21 row returns, measured by `program_shape`. A shared return would need a Rust map from argument values to rows instead (D2). |
| Denied call cost | p50 0.19–0.43 µs plain, p50 8.4–10.2 µs and p99 12.7–16.4 µs notified | 3 runs × 20,000 calls with a minimal supervisor. About 9 µs per round trip. With the real supervisor (`notification_cost`, "Accept when"): p50 13.6–30.0 µs on the dev host, 19.9 µs on CI x86_64 and 17.8 µs on CI arm64. |
| Spawn cost | 706–777 µs plain, 694–726 µs notified (3 of 4 runs; 1,071 µs in one) | `posix_spawn` + `waitpid` of `/bin/true`; within noise, because one `clone3` notification per spawn costs about 9 µs against about 700 µs. |
| Keys | 723 | D6's table. A larger table costs memory linearly; a smaller one would merge keys the agent needs apart (a family per key is what tells AF_VSOCK from AF_ALG). |
| Record bound | 723 × 144 bytes = 104,112 bytes per sandbox | `size_of::<Denial>()` is 144 on x86_64 (printed by `key_space_is_bounded`, which fails above 160). A flood cannot grow it. |
| errno range | 1 to 511 | One below `ERESTARTSYS` (512), where the kernel's internal codes start (D5). 0 would be a success; 512 to 531 restart the call or run its restart block; every uapi errno is at most 133. |
| Struct sizes | 80 / 24 / 64 bytes | `seccomp_notif`, `seccomp_notif_resp`, `seccomp_data` in the uapi header and in libc 0.2.191, pinned at compile time. |
| Status bound | 8,192 bytes | The dev host's longest `/proc/<pid>/status` among the user's processes was 1,542 bytes (measured 2026-11-28), a 5.3× margin. The bound keeps the read bounded: `Groups:` can grow to the 65,536 supplementary groups of `NGROUPS_MAX`, about 720 KB, and it comes before `NStgid:`, so such a file costs only the pid (`parse_status_forms` parses an `NStgid:` line ending at byte 8,192 and refuses one ending at 8,193). `Name:` and `Pid:` come first, so the comm survives. |
| Ceiling window | 472 to 511 | D6: about five to six years of new syscalls at the 2019–2026 rate. |
| Hang bound of the PR 2 stop and panic tests | 30 s | A bound, not a target: the kernel answers at once on detach (D4), so the measured time is printed and nothing asserts it. The bound turns a hang into a failed test instead of the `sandbox` job's 30-minute timeout, and two such tests stay far below that timeout. No test asserts a duration (#142's class of flakes). |

**Runner CPU under a flood of denied calls.** One supervisor thread per
sandbox, charged to the runner's cgroup rather than the sandbox's
`cpu.max`, so a workload spinning on denied calls costs at most one
runner core while it spends its own CPU on them. Repeated keys skip the
`/proc` reads, so a flood costs receive, evaluate and reply only. No rate
limit: a limit would be a number without data, and it would slow
spawn-heavy builds (make notifies one `clone3` per recipe line, D1). The
supervisor's CPU time per notification is 7.9 to 20.1 µs on the dev host
(`notification_cost`, "Accept when"), so one core answers on the order
of 50,000 to 125,000 denied calls a second.

## Consequences

- Every errno row's denial is visible to the run, with the call, its key
  arguments, the pid inside and the comm, once per key with a count.
- A workload's own filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER` gets
  EBUSY: a task may sit under only one filter with a listener
  (`has_duplicate_listener`, 5.19 `:1807`/`:1904`). Programs that run
  their own user-notification supervisor (a container runtime inside the
  sandbox) fail at that step.
- A runner that already runs under a listener filter (LXD/Incus syscall
  interception, sysbox) is refused by the probe (`seccomp-notify`).
- The pre-receive signal window (D4): a call interrupted before the
  supervisor received it returns EINTR and is missing from the record,
  or restarts and is counted once.
- Runner CPU (D8): S hostile sandboxes on one runner can take S runner
  cores. ARCHITECTURE's one-customer-per-VM rule bounds who pays for it.
- One more runner thread per sandbox.
- Another sandbox's child holds a copy of a listener only from its clone
  to its exec (the listener is close-on-exec in the runner,
  `MSG_CMSG_CLOEXEC`), which delays that sandbox's ENOSYS on supervisor
  loss by at most the other sandbox's setup timeout.
- The record is evidence for diagnosis, not a security log. A workload
  can keep a call out of it by stacking its own ERRNO filter (ERRNO
  outranks USER_NOTIF, 5.19 `:423`, the lower action wins) or a
  USER_NOTIF filter without a listener (which gives ENOSYS), but it never
  gets the call allowed.
- The plain program's shape changed (104 instructions, one return per
  row); its decisions did not.
- PR 1's code is unused until PR 2 lands, and if PR 2 finds a flaw in the
  hand-off, PR 1's types change while this ADR is proposed.

## Alternatives considered

- **`SECCOMP_FILTER_FLAG_LOG` and audit.** Audit records go to auditd or
  the kernel log. Both are host-global, both need privileges the runner
  lacks (`dmesg_restrict` is 1 on the dev host and both CI legs), and
  they need `CONFIG_AUDIT`.
- **`SECCOMP_RET_TRACE`.** It conflicts with strace and gdb inside the
  sandbox, which the debugging agent uses, and gives ENOSYS without a
  tracer.
- **`SECCOMP_RET_TRAP`.** It changes the workload's signals: a SIGSYS
  handler of the application would see the denials, and one without a
  handler dies.
- **Stacking an ERRNO filter on a notify filter.** ERRNO outranks
  USER_NOTIF, so nothing would be notified.
- **A supervisor in the sandbox or the shim** (D4): reachable by the
  workload.
- **`pidfd_getfd` for the hand-off** (D3): the child must wait for the
  parent, and Yama 2 and 3 refuse it.
- **A Rust mirror of the policy's errnos** (D2): could drift from the
  program.
- **One supervisor for all sandboxes**: a shared failure, where one
  sandbox's flood or one bug stops every record.
- **Replying with the continue flag** for any call: the call would run,
  which is the decision the filter exists to make.
- **A rate limit** (D8): a number without data, and slower builds.
- **An architecture-checker rule for the no-continue pin** (D5): a third
  always-review surface for the same names.
- **Language:** Rust in the existing crate. Nothing else was weighed: no
  new tool or crate is added, and the supervisor must live in the
  runner's process.

## Accept when

PR 2's host tests (`notified_rows_answer_as_plain_filter`,
`record_names_the_inside_pid_and_comm`, `every_notification_is_answered`,
`stopped_supervisor_leaves_calls_denied`,
`panicked_supervisor_leaves_calls_denied` and the rest of #45's plan) are
green on both CI legs and the dev host, with `notification_cost`'s
numbers and boneli-oci's `node` and `postgres` records recorded here.

Met on 2026-11-28 by part 2's PR. Every host test of boneli-sys, the
unit tests with a seam included, is green on the dev host (Fedora 44,
Linux 7.2.10 x86_64) and on both CI legs (Linux 7.0, x86_64 and arm64, CI run 46097425588: 20 unit and 85
integration host tests on each leg). Where each criterion is shown:

| Criterion | Test |
|---|---|
| Same errno with and without the listener, every notifying row (AC2) | `notified_rows_answer_as_plain_filter`: every form of `seccomp_rows`, the eight module ioctls on a memfd, the twelve Bpfilter forms on a Unix socket, `TCP_MD5SIG_EXT` and three ceiling forms, under the plain program on the host and in a sandbox for inside ids 0 and 999; each form's key is in the record, and the forms cover all 21 notifying rows (SockPacket only where af_packet is there) |
| The record names the call, its pid inside and its comm (AC1) | `record_names_the_inside_pid_and_comm`: a forked child's `socket(AF_ALG)`, pid 3 inside, comm `bnl-child` |
| Every notification is answered (AC4) | `every_notification_is_answered`: 8 threads × 1,000 calls, all EAFNOSUPPORT, count 8,000, one Clone3 entry |
| A lost supervisor leaves calls denied (AC4) | `stopped_supervisor_leaves_calls_denied`, `panicked_supervisor_leaves_calls_denied`, `inconsistent_notification_is_denied_and_fails` (unit tests with a seam, `src/seccomp/notify.rs`): the call it held or received and the next one get ENOSYS, `failed` says why; the held call returned 3 ms after the stop on the dev host and 4 ms on both CI legs (printed, not asserted) |
| A killed caller is not a failure | `killed_caller_is_not_a_failure`: `unanswered` 1, `failed` none |
| Signals | `signal_after_receive_keeps_the_errno`: the row's errno and the handler ran; `signal_before_receive_restarts_or_interrupts`: EINTR with no entry, or a restart with one (D4) |
| The runner stays usable | `set_id_calls_run_while_a_sandbox_runs`: `setgid(getgid())` from another runner thread returns while a sandbox runs, and a thread starts after it |
| The workload's filters never allow a call | `stacked_filters_never_allow`: EBUSY for a second listener, EACCES under its ERRNO filter, ENOSYS under its USER_NOTIF without a listener, neither recorded |
| The supervisor ends with its sandbox | `supervisor_ends_with_the_sandbox`, `listener_is_close_on_exec_in_the_runner` |
| The hand-off fails closed | `listener_hand_off_fails_closed` |
| The probe | `probe_notify_classification`; `reports_expected_missing` on both legs with the stock runner's set unchanged |

`notification_cost` (20,000 denied `socket(AF_VSOCK)` calls, each timed
in the probe; the supervisor's time on the CPU from its `schedstat`
divided by the notifications; 3 runs each on the dev host, one per CI
leg):

| Host | Build | Plain p50 / p99 | Notified p50 / p99 | Supervisor CPU per notification |
|---|---|---|---|---|
| dev host, `heavy.slice` | debug (as CI) | 0.24–0.62 / 0.49–1.26 µs | 13.6–30.0 / 24.6–141.6 µs | 8.9–20.1 µs |
| dev host, `heavy.slice` | release | 0.37–0.50 / 0.59–0.88 µs | 14.6–18.1 / 25.7–45.5 µs | 7.9–11.1 µs |
| CI `sandbox (x86_64)`, Linux 7.0 | debug | 0.39 / 0.46 µs | 19.9 / 30.4 µs | 11.4 µs |
| CI `sandbox (arm64)`, Linux 7.0 | debug | 0.27 / 0.30 µs | 17.8 / 21.1 µs | 8.5 µs |

The CI rows are one run each (the `sandbox` job runs the test once). So
a denied call costs about 15 to 20 µs with the real supervisor against
the planning harness's 9 µs: the supervisor polls, receives, evaluates the
plain program, takes the record's lock and replies, where the harness
only received and replied. The spawn cost of D8 is unchanged in kind:
one `clone3` notification per `posix_spawn` against about 700 µs.

boneli-oci's `node_and_postgres_run_in_sandbox` printed its records on
the dev host: `node --version` as inside id 0 and `postgres --version`
as 999 made no denied call (both records empty, `failed` none). Neither
starts a thread before it prints its version, so not even the Clone3
entry of D1 shows; a run with threads shows it
(`every_notification_is_answered`).
