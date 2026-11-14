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

## Invariants

1. **Crate graph:** `boneli-domain` → nothing; `boneli-app` → domain;
   adapters → domain, app and support crates; support crates (`boneli-sys`,
   `boneli-http`, `boneli-https`, ...) stay generic; composition roots
   (`boneli-runner`, `boneli-gw`, `boneli-egress`, `boneli-shim`,
   `boneli-cli`) wire adapters and nothing depends on them. The test-only
   root `boneli-replay-check` (ADR-002) is a leaf too.
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
   ADR-005). The approval is per crate, not per version (ADR-005).
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

## Validation (CI equivalent — run before every commit)

Once per machine: `rustup target add x86_64-unknown-none`. The architecture
check needs Python 3.11 or newer.

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
cgroup v2 hierarchy whose cgroup the tests run in is delegated to the user
with the cpu, io, memory and pids controllers, Landlock ABI 2 and Linux
5.19 (ADR-007, D3 and D5). They never need root and never call `sudo`; a
missing feature fails them with the probe's message instead of skipping
them. Run them in a delegated scope:

```sh
systemd-run --user --scope -q -p Delegate=yes \
  env BONELI_SYS_TEST_CGROUP=self BONELI_SYS_HOST_GAPS= \
  cargo test -p boneli-sys -- --ignored
```

- `BONELI_SYS_EXPECT_MISSING`: unset or empty, the probe test requires
  that the host lacks nothing; set to a comma-separated list of probe ids
  (`userns-apparmor`, `cgroup-not-delegated`, ...), it requires exactly
  that set. CI uses it to prove the error a stock runner gives.
- `BONELI_SYS_HOST_GAPS`: kernel rows of the seccomp policy this host
  cannot observe, by id. Exact: an unknown id fails, and so will a listed
  row that turns out observable. Empty until the seccomp rows exist.
- `BONELI_SYS_TEST_CGROUP=self`: the scope was started for this test run,
  so the harness may reorganize its own cgroup: it moves the run's
  processes into `leaf/` and creates every sandbox's cgroup next to it
  (ADR-007, D8). Without it every host test that starts a sandbox
  fails. Never set it in a terminal whose cgroup holds other processes.

**Preparing a host** takes the block below, run once with root through
`sudo`. CI runs exactly this block (it extracts it between the markers),
so a user and CI prepare a host the same way. Inputs: `TARGET_DIR`,
cargo's target directory; `RUN_USER`, the user who runs the tests;
`ENABLE_LINGER=1` on hosts without a login session.

1. **AppArmor** (only where `kernel.apparmor_restrict_unprivileged_userns`
   is 1): a profile that allows user namespaces for the two `boneli-sys`
   test binaries only, `boneli_sys-<hash>` and `boneli_sys_tests-<hash>`
   under `$TARGET_DIR/<profile>/deps/` (cargo before 1.100) or
   `$TARGET_DIR/<profile>/build/boneli-sys/<hash>/out/` (cargo 1.100's
   build directory layout). Everything else on the host keeps
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
# 1. AppArmor (Ubuntu 23.10+): allow user namespaces for the boneli-sys test binaries only.
if [ "${APPARMOR_USERNS:-$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)}" = 1 ]; then
  sudo tee /etc/apparmor.d/boneli-sys-tests >/dev/null <<EOF
abi <abi/4.0>,
include <tunables/global>
profile boneli-sys-tests $TARGET_DIR/*/{deps,build/boneli-sys/[0-9a-f]*/out}/boneli_sys{,_tests}-[0-9a-f]* flags=(unconfined) {
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
