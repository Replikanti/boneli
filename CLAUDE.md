# CLAUDE.md — boneli

Boneli reproduces bugs in a replica of the application with data, finds the
root cause with verified evidence and opens the fix as a pull request. This
repository holds everything that runs at the customer: domain, application,
sandbox runtime, shim, gateway, egress, adapters, runner, CLI and the bench
harness. Rust workspace, hexagonal architecture. Public repository
(Apache-2.0).

## Sources of truth

- Design: `docs/ARCHITECTURE.md` is the design baseline.
- Decisions since: `docs/adr/` (process in its README). A PR that makes a
  design decision adds or flips an ADR.
- Work: GitHub issues, labelled `area::*`, `P1`–`P3`, `size::*`, `epic`,
  `needs-adr`. The pinned "Task ledger" issue lists them in processing order.
- Releases: `docs/release.md` (versioning, the tag recipe, what ships:
  `tools/release-packages`; ADR-019). `sh tools/test-release.sh` tests the
  release tooling.

## Invariants

1. **Crate graph:** `boneli-domain` → nothing; `boneli-app` → domain;
   adapters → domain, app and support crates; support crates (`boneli-sys`,
   `boneli-http`, `boneli-https`, ...) stay generic; composition roots
   (`boneli-runner`, `boneli-gw`, `boneli-egress`, `boneli-shim`,
   `boneli-cli`) wire adapters and nothing depends on them. The test-only
   roots `boneli-replay-check` (ADR-002) and `boneli-acceptance` (live
   tests, ADR-014 D12) are leaves too, and so is the tool root
   `boneli-arch-check`, the architecture checker itself (ADR-015).
   `tools/check-architecture.sh` enforces it.
2. **Core purity** (domain, app): no external dependencies, no wall clock,
   filesystem, network, environment, threads, processes, async or
   `HashMap`/`HashSet`. Runs replay deterministically from the event log.
   Both crates are `#![no_std]` with `alloc` and must build for
   `x86_64-unknown-none`; a token scan covers what `no_std` cannot remove
   (async, `core::arch`, atomics, pointer addresses, format specs that end
   in `p` in any file of the package and after escapes, `concat`,
   `stringify`, `env`, `option_env`, glob imports from `fmt`, `use` items
   built from macro metavariables, `core::task` and its wakers, `{` or `}`
   in core file paths, `include_str!` paths that are absolute or contain
   `..` or a backslash). The scan is a best-effort first layer; the gate for address
   leaks is the two-process replay test in `boneli-replay-check`, which
   folds the domain's scenario corpus (ADR-002) and plays the app corpus,
   `DebugTicket` on the in-memory adapters with every fault kind injected at
   every port call (ADR-004), as decided at STOP 2 of #28, and compares
   the violation of every contract mutant too (ADR-004, D10). Dependency
   `cfg`s of core crates are also
   evaluated on `x86_64-unknown-none` (ADR-001).
3. **Pure Rust, minimal dependencies:** every edge into an external crate,
   transitive ones included, needs a record with a reason in
   `tools/architecture.toml`; a new crate name needs an ADR or a row in
   ARCHITECTURE, and every edge into `libc` needs its own accepted ADR that
   names it. Edges count unless their `cfg` is false on every checked Linux
   target (x86_64 and aarch64, gnu and musl); flag-dependent cfgs such as
   `crt-static` count as true. Sources are crates.io only; path dependencies
   point to members. The "do not use" list is enforced in `deny.toml`.
   Widening either needs an ADR (ADR-001).
4. **Unsafe only in `boneli-sys`.** Every other crate inherits the workspace
   lints, which forbid it; the check also scans every other crate for the
   `unsafe` token and requires the doctest attribute
   `#![doc(test(attr(forbid(unsafe_code))))]` in its lib root. `boneli-sys`
   has its own `[lints]` table instead (rule `sys-lints`): every workspace
   lint except `unsafe_code` at the same or a stricter level, the lints of
   `[check] unsafe-lints` (`unsafe_op_in_unsafe_fn`,
   `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`,
   `unwrap_used`) at `forbid`, so no inner `#![allow]` can lower them, and
   nothing else below `deny` (ADR-007, D6). No
   `.cargo/config*`, `clippy.toml`, `rust-toolchain*`, proc-macro crate,
   `#[path]`, `include!` or target source outside `.rs`; no build script in
   a member outside `roles.build-script` in `tools/architecture.toml` (empty;
   adding a crate needs an ADR) (ADR-001). A build script in an external
   dependency needs an accepted ADR that approves it for that crate in
   the sentence `<crate>'s build script is approved`: the key
   `build-script = "ADR-NNN"` on its `[external.<crate>]` record, required
   by the check for every reachable external crate whose cargo metadata
   has a build script (`httparse`: ADR-003; `libc`, `ring`, `rustls`:
   ADR-005; `num-traits`: ADR-016). The approval is per crate, not per
   version (ADR-005).
5. **The sandbox holds no secrets and has no network.** Capabilities reach it
   only through broker sockets. The MVP subscription token is the one
   documented exception.
6. **Gates are deterministic and fail closed.** A fix is verified in a clean
   sandbox from the base SHA and the diff only; nothing from the agent's
   sandbox is trusted.
7. **Ports are synchronous traits** in `boneli-app` (std threads, no async
   runtime). Every port has an in-memory adapter in `boneli-memory` and a
   contract suite in `boneli_app::contract` that the real adapters reuse;
   every clause has a mutant in `boneli-replay-check` that fails it
   (ADR-004).
8. **File locks only through `boneli_private_dir::lock`** (ADR-030), rule
   `file-lock`: its `FileLock` and `HandOff` hold the release rule (unlock
   before close, only the owner unlocks, owner = pid + pid namespace).
   Everywhere else the check fails raw lock names (`flock`, `LOCK_EX`,
   ...) and the `File` lock methods; Mutex and stdio locks pass only as
   `Mutex::lock(&m)`, `m.lock().unwrap_or_else(PoisonError::into_inner)`,
   `m.try_lock().as_deref()` or `io::stdout().lock()`, never inside a
   macro. `#[cfg(test)] mod` blocks and integration tests under `tests/`
   are not scanned.

## Validation (CI equivalent — run before every commit)

Once per machine: `rustup target add x86_64-unknown-none`.
`tools/check-architecture.sh` builds the checker (`boneli-arch-check`) into
`target/arch-check` on first use and then runs it (ADR-015).

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
tools/check-architecture.sh
tools/check-architecture.sh --fixtures
cargo deny check
```

CI also runs `cargo check -p boneli-sys --all-targets --target <t>` for
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (once per
machine: `rustup target add` both).

### Host tests (boneli-sys)

`boneli-sys` creates user namespaces, so its host tests are
`#[ignore = "host: ..."]` and need a prepared host: unprivileged user
namespaces (on Ubuntu 23.10+ an AppArmor profile that allows them), a
cgroup v2 hierarchy mounted with `nsdelegate` whose cgroup the tests run in
is delegated to the user with the cpu, io, memory and pids controllers,
Landlock ABI 2 and Linux 6.1 (ADR-007 D5, ADR-044). They never need root
and never call `sudo`; a missing feature fails them with the probe's
message instead of skipping them. Run them in a delegated scope:

```sh
systemd-run --user --scope -q -p Delegate=yes \
  env BONELI_SYS_TEST_CGROUP=self BONELI_SYS_HOST_GAPS=syslog,shmget-hugetlb \
  cargo test -p boneli-sys -- --ignored
```

- `BONELI_SYS_EXPECT_MISSING`: unset or empty, the probe test requires
  that the host lacks nothing; set to a comma-separated list of probe ids
  (`userns-apparmor`, `cgroup-not-delegated`, ...), it requires exactly
  that set. CI uses it to prove the error a stock runner gives.
- `BONELI_SYS_HOST_GAPS`: what this host cannot show, by id (ADR-007, D5).
  `syslog`: the host gives EPERM to `syslog` without the filter already
  (`kernel.dmesg_restrict` 1); `shmget-hugetlb`: likewise for
  `shmget(SHM_HUGETLB)` (the user is outside `vm.hugetlb_shm_group` and
  lacks `CAP_IPC_LOCK`); `socket-inet-packet` and `ioctl-siocgifbr`: the
  host lacks af_packet (no `/proc/net/packet`) or the bridge module (no
  `/sys/module/bridge`), so the test does not try that row, which would
  load the module; `setsockopt-tcp-ao` and `setsockopt-tcp-md5`: the
  kernel lacks the option; `nosys-<name>`: the host kernel lacks the `NeedsCap` census
  syscall `<name>`; `alarm-rtc`: the host has no RTC alarm device, so
  `timer_create` and `clock_nanosleep` on an alarm clock answer
  EOPNOTSUPP before their capability check; `hugetlbfs-mount`: the host
  has no hugetlbfs mount. Exact: an unknown id fails, and so does a listed id that turns
  out observable. The command above has the dev host's value (Fedora 44,
  measured); CI sets it per leg in `.github/workflows/ci.yml`. The kTLS
  row is no gap id: whether the `tls` ULP is there differs between hosts
  of one image, so the test reads `/proc/sys/net/ipv4/tcp_available_ulp`
  and requires the row observed where it lists `tls`.
- `BONELI_SYS_TEST_CGROUP=self`: the scope was started for this test run,
  so the harness may reorganize its own cgroup: it moves the run's
  processes into `leaf/` and creates every sandbox's cgroup next to it
  (ADR-007, D8). Without it every host test that starts a sandbox
  fails. Never set it in a terminal whose cgroup holds other processes.

Every sandbox these tests start runs without capabilities, with
`no_new_privs` and under the seccomp policy (ADR-007, D2 and D9); so do
boneli-oci's sandbox runs below. Its errno rows are answered by a
supervisor thread (`seccomp-notify`) in the test process, which records
each denied call (ADR-043); the probe id `seccomp-notify` names a host
whose kernel lacks the wait-killable receive (a feature of 5.19) or
whose runner already sits under a seccomp filter with a listener, and
`kernel-floor` a kernel whose pids controller has no `pids.peak`, so one
older than 6.1 (ADR-044). The supervisor tests that need a seam (a lost supervisor, a killed caller,
signals around the receive) are unit tests in
`src/seccomp/notify.rs`, which re-run the unit-test binary in the
sandbox; `notification_cost` prints what a denied call costs with and
without the listener. `Unproven` census entries print with
their reason outside libtest's capture on every run.

### Host tests (boneli-oci)

`boneli-oci`'s host and network tests live in one target,
`boneli_oci_tests`, with the same host needs and the same harness
variable (ADR-009). `host::` mounts a pulled synthetic image in the
sandbox, and checks a casefold store root (tmpfs `casefold`, Linux 6.13;
list `tmpfs-casefold` in `BONELI_OCI_HOST_GAPS` where the kernel lacks it),
a ramfs root through `unshare -Urm`, a store opened in a PID
namespace without its own `/proc` through `unshare -Urpfm`, and that a
second store's trim with a budget of 1 keeps the layers of a running
sandbox (`mounted_layers_survive_trim`, ADR-025). `network::` pulls
`node:22` and `postgres:17` from Docker Hub as references the agent chose,
under the first-stack exemption `docker.io` + `library/` (ADR-032), and
runs them, and checks
image signatures (ADR-029): `signatures_on_docker_hub` pulls the signed
`chainguard/node` under a `Required` rule and refuses the unsigned
`node:22` with no layer request (and the agent's `node:22` with no
connection), and `signatures_elsewhere` pulls signed
images from GHCR, `cgr.dev` and Artifact Registry;
`provenance_claims_on_ghcr` pulls jq from GHCR under a rule with SLSA
provenance claims and refuses it under another source repository
(ADR-031), `certificate_claims_on_ghcr` pulls it under Fulcio
certificate claims with the statement agreement and refuses it under
another build trigger (ADR-034), and `provenance_v02_on_ghcr` does the
same as `provenance_claims_on_ghcr` for flux-cli's SLSA v0.2 provenance
in a cosign `.att` (ADR-036), and `signatures_on_rekor_v2` pulls
bex-cnb-run from GHCR, signed through a Rekor v2 entry with its time from
an RFC 3161 timestamp, and refuses it under another SAN (ADR-038); CI
runs them in the weekly
`oci-acceptance` workflow, not on every PR. `proxy::node_pulls_through_the_proxy`
pulls `node:22` through the HTTP proxy named by `BONELI_OCI_TEST_PROXY`
(`host:port`, ADR-039) and fails, naming the variable, when it is unset;
`oci-acceptance` runs it through Squid with direct outbound 80 and 443
rejected for the runner user.

```sh
systemd-run --user --scope -q -p Delegate=yes \
  env BONELI_SYS_TEST_CGROUP=self \
  cargo test -p boneli-oci --test boneli_oci_tests -- --ignored host::
```

**Preparing a host** takes the block below, run once with root through
`sudo`. CI runs exactly this block (it extracts it between the markers),
so a user and CI prepare a host the same way. Inputs: `TARGET_DIR`,
cargo's target directory; `RUN_USER`, the user who runs the tests;
`ENABLE_LINGER=1` on hosts without a login session.

1. **AppArmor** (only where `kernel.apparmor_restrict_unprivileged_userns`
   is 1): a profile that allows user namespaces for the `boneli-sys` and
   `boneli-oci` test binaries only, `boneli_{sys,oci}-<hash>` and
   `boneli_{sys,oci}_tests-<hash>` under `$TARGET_DIR/<profile>/deps/`
   (cargo before 1.100) or `$TARGET_DIR/<profile>/build/boneli-{sys,oci}/<hash>/out/`
   (cargo 1.100's build directory layout). Everything else on the host keeps
   the restriction; what the test binaries exec inherits the profile. Undo: `sudo apparmor_parser -R
   /etc/apparmor.d/boneli-sys-tests && sudo rm
   /etc/apparmor.d/boneli-sys-tests`. Builds with `--target <triple>` sit
   one directory deeper and are not matched. **The profile grants user
   namespaces to whatever sits at those paths, and the building user can
   write them**: on a shared or desktop host that lifts the restriction
   for that user. A production runner needs a root-owned binary path
   (#8).
2. **cgroup delegation**: user managers get the cpu, io, memory and pids
   controllers (systemd delegates only some by default; io is the one
   usually missing). Undo: remove the drop-in and `sudo systemctl
   daemon-reload`. A desktop session needs a re-login before it applies.
3. **Linger** (`ENABLE_LINGER=1`): a user manager without a login, which
   `systemd-run --user` needs on CI and servers; it is restarted so the
   delegation applies, and the block waits for its bus (30 s is a hang
   bound, not a target). Undo: `sudo loginctl disable-linger "$RUN_USER"`.

The checks on `TARGET_DIR` keep AppArmor glob and quoting characters out
of the profile (the path must match `[A-Za-z0-9._/-]`, before and after
it is resolved) and refuse `/`, which would turn the glob into one over
the whole filesystem; `realpath` because AppArmor matches the resolved
exec path. `crates/boneli-sys/tests/boneli_sys_tests/host_setup.rs` runs
the block against a fake `sudo`.

<!-- host-setup:begin -->
```sh
# Inputs: TARGET_DIR (cargo's target dir), RUN_USER (who runs the tests),
# ENABLE_LINGER=1 on hosts without a login session (CI, servers);
# APPARMOR_USERNS=1 or 0 overrides the sysctl check of step 1.
set -eu
export LC_ALL=C
check_target_dir() {
  case $1 in
    / | *[!A-Za-z0-9._/-]*) echo "host-setup: TARGET_DIR must not be / and must match [A-Za-z0-9._/-]" >&2; exit 2 ;;
  esac
}
check_target_dir "$TARGET_DIR"
TARGET_DIR=$(realpath -e -- "$TARGET_DIR")
check_target_dir "$TARGET_DIR"
# 1. AppArmor (Ubuntu 23.10+): allow user namespaces for the boneli-sys and boneli-oci test binaries only.
if [ "${APPARMOR_USERNS:-$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)}" = 1 ]; then
  sudo tee /etc/apparmor.d/boneli-sys-tests >/dev/null <<EOF
abi <abi/4.0>,
include <tunables/global>
profile boneli-sys-tests $TARGET_DIR/*/{deps,build/boneli-sys/[0-9a-f]*/out,build/boneli-oci/[0-9a-f]*/out}/boneli_{sys,oci}{,_tests}-[0-9a-f]* flags=(unconfined) {
  userns,
}
EOF
  sudo apparmor_parser -r /etc/apparmor.d/boneli-sys-tests
fi
# 2. cgroup v2: delegate cpu, io, memory and pids to user managers.
sudo mkdir -p /etc/systemd/system/user@.service.d
printf '[Service]\nDelegate=cpu io memory pids\n' | sudo tee /etc/systemd/system/user@.service.d/boneli-delegate.conf >/dev/null
sudo systemctl daemon-reload
# 3. Headless hosts: a user manager without a login, restarted so the delegation applies.
if [ "${ENABLE_LINGER:-0}" = 1 ]; then
  sudo loginctl enable-linger "$RUN_USER"
  sudo systemctl restart "user@$(id -u "$RUN_USER").service"
  i=0; until [ -S "/run/user/$(id -u "$RUN_USER")/bus" ]; do
    i=$((i + 1)); [ "$i" -le 30 ] || { echo "host-setup: no user bus after 30 s" >&2; exit 1; }; sleep 1
  done
fi
```
<!-- host-setup:end -->

### Live test (boneli-forge-github)

`boneli-acceptance`'s `tests/github.rs` runs the real git adapter and the
GitHub forge against the operator's GitHub App and private test
repository (ADR-014, D12). It is `#[ignore = "network: ..."]`, runs by
hand before a change to `boneli-forge-github` or to the git push and
credential path merges, and fails, naming the variable, when one of the
`BONELI_GITHUB_*` variables is missing. Setup: `docs/forge-github.md`.

```sh
cargo test -p boneli-acceptance --test github -- --ignored --nocapture
```

### Interop and live test (boneli-https)

The hybrid key exchange X25519MLKEM768 (ADR-016) has two ignored tests
next to the local ones. `tests/interop.rs` runs 32 handshakes against
`openssl s_server` and needs OpenSSL 3.5 or newer on PATH; it fails, not
skips, without it or without the group. CI runs it in `check` on every
PR. `tests/network.rs` checks the group against
pq.cloudflareresearch.com and runs by hand before a change to
`crates/boneli-https/src/pq.rs` or to the key exchange group lists of
`TlsConfig` merges. It also holds the revocation live tests (ADR-017):
Let's Encrypt's revoked test site must fail with `Error::Revoked`, its
valid one must be checked against its CRL, and the revocation status of
the runner's hosts is printed. For OCSP (ADR-020) the six forge hosts
whose leaves name only an OCSP responder (GitHub, GHCR, GitLab) must be
`OcspChecked` by Sectigo's responder, and for the intermediates (ADR-027)
`intermediates_checked_live` checks Let's Encrypt's, GitHub's and the
runner's chains against their CA lists; the crate's `ocsp::live` tests
check SSL.com's revoked test leaves and two delegated responders
(`pypi.org`, `www.microsoft.com`) through the OCSP path directly. Run
them by hand before a change under `crates/boneli-https/src/revocation/`
merges. `tests/network.rs` also compares the name resolver of ADR-022
with the system's on the runner's hosts
(`own_resolver_agrees_with_the_system`); run it by hand before a change
under `crates/boneli-https/src/resolve/` merges.

```sh
cargo test -p boneli-https --test interop -- --ignored
cargo test -p boneli-https --test network -- --ignored --nocapture
cargo test -p boneli-https --lib -- --ignored ocsp::live
```

### Live test (boneli-tuf)

`tests/network.rs` refreshes `trusted_root.json` from Sigstore's TUF
repository `tuf-repo-cdn.sigstore.dev` over `TlsDial`, from the pinned
root v16 (`tests/data/sigstore-16.root.json`) into an empty trust
directory and once more, which must find the file current (ADR-033).
`github_refresh_live` does the same for GitHub's private-repository root
from `tuf-repo.github.com`, from the pinned root v3
(`tests/data/github-3.root.json`), and verifies two captured
private-repository attestations under the installed file with the no-log
opt-in of ADR-040 (ADR-041). Both print the versions, the run time and
the target's SHA-256. CI runs them in the weekly `oci-acceptance`
workflow on both architectures; run them by
hand before a change under `crates/boneli-tuf/src/` merges. Operator
setup: `docs/sigstore-trust.md`.

```sh
cargo test -p boneli-tuf --test network -- --ignored --nocapture
```

## Conventions

- English in code, comments, commits, PRs and issues.
- Branch and PR for every change; never push to main. The PR body carries
  `Closes #N` or a
  `No-Issue: <reason>` line (CI-enforced).
- Domain items cite the design section or ADR they implement.
- Every new dependency is justified in a `Cargo.toml` comment; licenses per
  `deny.toml`. Core crates take none.
- Changes go to `CHANGELOG.md` under `## [Unreleased]`.
- **Public repository:** no local paths, credentials, API keys or private
  data. Agent prompts and playbooks, benchmark cases, pricing and strategy
  belong to the private `Replikanti/boneli-cloud`, never here. Only the
  playbook and case *formats* are defined in this repository.
