# ADR-014: GitHub forge: App tokens, create-only branch push through the Git port, inert pull-request bodies

- Status: proposed
- Date: 2026-11-19

## Context

Issue #19 builds the first real adapter of the `Forge` port (ADR-004):
`boneli-forge-github`, which posts triage questions on a GitHub issue and
opens the pull request with the verified fix. A pull request needs a
branch on the customer's repository that holds the fix, so the adapter
pushes one before it calls the GitHub API. That branch and the token that
pushes it are where this ADR starts:

- ADR-004 (D11) gives the repository to the `Git` port, and ADR-010 (D4)
  fixes how a token may reach the host git: only as
  `http.<url>.extraHeader` in the command-scope config of the one git
  process that needs it, never in argv, a file or the snapshot. It names
  that rule "the rule for #19".
- The runner pushes to a repository whose `main` a human owns. A push
  that names the wrong ref, or moves a ref that exists, writes into the
  customer's history with the customer's token.
- The token comes from a GitHub App installation and lives for an hour
  (D5, part 3), so a long run needs a fresh value per git process, not
  one value read at start.

#19 is delivered in three PRs. Part 1 (this ADR's D1 to D3) adds branch
push to the `Git` port and to `boneli-git-cli`, with the credential path,
and carries the verified citations into the pull-request request. Part 2
adds RS256 signing and a random source to `boneli-https` and moves the
`Dial` seam there from `boneli-oci` (D4). Part 3 adds
the forge crate, its token cache, endpoints, rendering and limits (D5 to
D11) and the gated live test (D12), and settles this ADR.

Decided at #19 STOP 1 (2026-11-19): `boneli-forge-github` joins the list
of crates that always get an adversarial review; the live test runs by
hand before part 3 merges and on any change to the forge or to the git
push and credential path, with no App key in this repository's secrets;
a pull request for a GitHub ticket of the same repository carries
`Fixes #N`; pull requests open ready for review.

## Decision

### D1. The push goes through the `Git` port

`Git` gains one operation:

```rust
fn push(&self, checkout: &CheckoutId, branch: &BranchName, commit: &CommitInfo)
    -> Result<CommitSha, GitError>;
```

It commits the checkout's tree with the base commit as the only parent
and pushes that commit to a new branch of the repository the base was
fetched from. The forge composes `fetch_base` → `apply` (the verified
diff) → `push` → create the pull request (part 3). The port takes no URL:
a checkout knows its repository, so a push can only go back where the
base came from.

- **Why the base as the only parent:** the pull request then shows the
  verified diff and nothing else. The verifier checked that diff against
  that base (invariant 6), so any other parent would ship a tree nobody
  verified.
- **The contract** (`boneli_app::contract::git`) gains four clauses, each
  with a mutant in `boneli-replay-check` (ADR-004, D2):
  - `push-reads-back`: the pushed commit is the branch's tip on the
    remote, and fetched again it holds the applied tree (mutant: push
    the base's tree);
  - `push-parent-is-base`: the tip's parents are exactly `[base]`
    (mutant: an orphan commit);
  - `push-never-overwrites`: a second push to the branch is
    `BranchExists` and the tip stays (mutant: a forced push);
  - `push-unknown-checkout`: `UnknownCheckout`, and no branch appears
    (mutant: `Failed`).

  The suite reads the remote through a new fixture hook, `Remote<G>`,
  because only the adapter's own test can see it: the host git on the
  fixture repository for `boneli-git-cli`, the adapter's state for
  `MemoryGit`. Each clause uses its own branch,
  `boneli/contract-<clause>`, which must be absent before it pushes (a
  fixture violation otherwise, so a leftover branch cannot make a push
  that never happened read back). The counts are now 54 clauses and 66
  mutant cases (`mutant_table_covers_every_clause`).
- **`MemoryGit`** records pushed commits and branches in its state.
  Commit ids are `0…0<n>` in hex from a counter, as long as the base's
  id, so a replayed run gets the same ids; an id a fixed commit already
  has is refused (`Failed`), never shadowed. A pushed commit can be
  fetched like a fixed one, which `push-reads-back` needs.

### D2. Branches: create-only, under `boneli/`

- **`BranchName`** is `boneli/` followed by one component of 1 to 100
  bytes of `[a-z0-9._-]` that starts and ends with `[a-z0-9]`, holds no
  `..` and does not end in `.lock`. That is a strict subset of
  `git check-ref-format --branch` (pinned by
  `every_branch_name_passes_check_ref_format`), so the port can never
  name `main`, a tag or any branch outside `boneli/`, and no name needs
  quoting anywhere it travels (a refspec, a URL query, a forge's API).
  Uppercase is out because branches on case-insensitive file systems
  collide when only case differs.
- **The forge's names** (part 3) are `boneli/<run-slug>-<8 hex nonce>`.
  The slug keeps `[a-z0-9]`, lowercases `[A-Z]` and maps every other
  byte to `-`; runs of `-` are collapsed and trimmed, the result is cut
  to 40 bytes, and an empty slug becomes `run`. The nonce exists because
  the `Forge` suite's `distinct-references` clause opens two pull
  requests from one request, so one run must be able to push twice; two
  attempts of one run collide with probability 2^-32, and a collision
  fails closed (`BranchExists`).
- **Why 100 bytes:** the longest forge name is 7 + 40 + 1 + 8 = 56
  bytes (a 49-byte suffix), so 100 leaves room for another forge's
  longer names. A remote that stores the branch as a loose ref writes
  the suffix as one file name, `<suffix>.lock` while it updates it, so
  105 bytes against the 255-byte `NAME_MAX`. A cap below 49 bytes would
  refuse the forge's own names; one above 250 would let such a remote
  fail to write the ref.
- **Create-only.** `boneli-git-cli` first asks the remote for the exact
  ref (`ls-remote --refs -- <url> refs/heads/<branch>`); a branch that
  exists is `BranchExists` and nothing is pushed. Then it pushes with
  `--force-with-lease=refs/heads/<branch>:`, whose empty expected value
  means "must not exist", so a branch created between the check and the
  push is refused by the remote too. Checked on git 2.56.0: that lease
  refused even a fast-forward over an existing branch and left its tip
  unchanged (`push_lease_refuses_a_branch_created_after_the_check` fakes
  the race with a git whose first `ls-remote` answers nothing).
  After a failed push the remote is asked again: a tip that is another
  commit is `BranchExists`, a tip that is the pushed commit means the
  push landed and only its answer was lost (until the push, that commit
  exists only in the adapter's store), and anything else is the push's
  own error.
- **The push command** is `push --porcelain --no-verify
  --force-with-lease=<ref>: -- <url> <commit>:<ref>`. `--` before the
  URL works on git 2.56.0; the URL is checked against the transports
  (ADR-010, D5) again before any process starts. The command scope adds
  `push.recurseSubmodules=no`, `push.followTags=false` and
  `push.gpgSign=false`, so a push sends the one ref it names and asks for
  no signing that the remote could demand.
- **What it sends: `push.negotiate=true`.** The store holds the base at
  depth 1 and has no refs. Without negotiation, `git push` leaves out
  only what the remote's advertised tips reach and the store has; once
  the remote's `main` has moved past the base (or the base is no tip),
  the store has none of them, and git sends the base commit and its
  whole tree. With `push.negotiate=true` the push first runs a child
  `git fetch --negotiate-only` that finds the base as a common commit,
  and sends only what is new. Measured on git 2.56.0 by
  `push_sends_only_new_objects`, a base with 300 files beside the edited
  one and a one-file change:

  | `main` on the remote | without negotiation | with negotiation |
  | --- | --- | --- |
  | at the base | 4 objects | 4 objects |
  | moved past the base | 309 objects | 4 objects |

  The 4 are the commit, the root and `src` trees and the blob. The test
  measures what the push's `pack-objects` wrote (git's trace2 data
  `write_pack_file/wrote`), not the remote's object count, which cannot
  see objects the remote already had; it also reads the pack the remote
  kept (`receive.unpackLimit=1`): exactly 4 objects new to the remote,
  plus at most one delta base per delta sent, which the remote appends
  from its own objects to complete a thin pack (`index-pack
  --fix-thin`). The first version of this ADR measured the remote's
  object growth and missed the 309 (review round 1 of #71).
  - **When negotiation fails** (checked on git 2.56.0 by forcing protocol
    v0, which `--negotiate-only` refuses), git warns "push negotiation
    failed; proceeding anyway with push" and sends the full set as
    without negotiation. The push still lands; it only costs bandwidth.
  - **Open item:** whether GitHub answers the negotiation of a shallow
    client, so that a push from the depth-1 store sends 4 objects there
    too, is not verified yet. The live test of part 3 checks it ("Accept when");
    the fallback above keeps the push correct either way.
- **`CommitInfo`** is the author and committer of the pushed commit and
  its message, set through `GIT_AUTHOR_*` and `GIT_COMMITTER_*` on
  `commit-tree` only, with the message on stdin (`-F -`):
  - the name is 1 to 128 bytes, not blank, with no control character,
    `<` or `>`, which would end git's ident early or split the commit
    header. git sets no limit; the name comes from the operator's
    configuration (a GitHub App's bot login in part 3), never from the
    agent, so 128 is a sanity bound that stops a misconfigured value from
    writing an unbounded header, chosen well above any bot login. A lower
    cap risks refusing a real bot or person name; a higher one changes
    nothing but the size of a commit a misconfiguration can produce;
  - the email is 3 to 254 bytes of visible ASCII, contains `@` and has
    no `<` or `>`. 254 is the longest address that fits RFC 5321's
    256-octet path, which includes the two angle brackets; 3 is the
    shortest form `a@b`;
  - the message is not blank, has no NUL (a commit message is text, and
    a NUL would hide what follows it from most readers) and is at most
    65,536 bytes. The forge generates it (part 3: a
    summary line naming the ticket and the run id, with no closing
    keyword), so it stays under a few hundred bytes; the cap bounds what
    the adapter writes to git's stdin if a caller passes something else.
    A cap below a generated message would fail every push; a higher one
    only admits larger commit objects.

### D3. Credentials into git

`boneli-git-cli` exports `Credentials`:

```rust
pub trait Credentials: Send + Sync {
    fn authorization(&self, url: &RepoUrl) -> Result<Option<String>, String>;
}
```

`GitCliConfig.credentials: Option<Arc<dyn Credentials>>` holds the
source. The ADR-010 D4 rule applies, plus these choices:

- **Scoped to the exact repository URL.** The value reaches git as one
  more command-scope pair, `http.<url>.extraHeader` = `Authorization:
  <value>`, where `<url>` is the URL git is given after `--`.
  `http.followRedirects=false` (ADR-010, D4) keeps a redirect from
  carrying the header to another URL.
- **Only network calls carry it:** `fetch` (the base and the probe of
  ADR-010 D6), `ls-remote` and `push`. `init`, `read-tree`, `add`,
  `write-tree`, `ls-tree`, `cat-file`, `apply`, `commit-tree` and
  `pack-objects` get none (`authorization_only_on_network_calls`), and
  no argv ever holds it. The push's own children inherit its
  environment, so they read the same pair: the negotiation fetch
  (`push.negotiate`, D2), which talks to the same URL and needs it
  (`negotiation_fetch_carries_the_scoped_header`, from git's trace2
  log of the config each process read), and the push's `pack-objects`,
  which reads it and makes no request.
- **Fetched fresh for each process.** A source that mints tokens with an
  hour's life can refresh between the calls of one operation; the value
  for the first network call of `fetch_base` and `push` is taken before
  any process starts, so a source that fails starts nothing
  (`credentials_error_fails_closed`).
- **The value is checked before use:** 1 to 8,192 bytes of `0x20`-`0x7E`
  with no space at either end. CR, LF and NUL cannot get in, so the value
  cannot inject a second header or cut the config value; a refusal names
  the rule, never the value (`header_value_rules`). Why 8,192: the
  Basic form of a token is `Basic ` plus the base64 of
  `x-access-token:<token>`, about 5,490 bytes for a 4,096-byte token, the
  cap part 3 sets on installation tokens (D5); 8,192 holds that with
  room and stays far below Linux's limit on one environment string
  (`MAX_ARG_STRLEN`, 128 KiB), past which git would not start. A lower
  cap would refuse tokens part 3 accepts; a higher one only admits
  larger headers.
- **Failure details are redacted.** The detail of a call that carried a
  value has the value, and its part after the scheme, replaced by
  `[redacted]`; a git that prints its whole environment to stderr shows
  that (`failure_detail_redacts_authorization`). The snapshot's
  generated `.git` has no http config and never sees the value
  (`snapshot_never_carries_authorization`).
- **Residual:** the environment of a running git process is readable by
  the same uid and by root. Both already hold what mints the token (the
  App key, part 3), so the environment discloses nothing they lack; argv,
  which every user can read in `/proc`, never holds it.

### D4. Signing, randomness and the `Dial` seam live in `boneli-https`

A GitHub App authenticates by signing a JWT with its RSA private key
(RS256), and part 3 needs random bytes for the branch nonce (D2) and an
HTTPS connection to `api.github.com` with a deadline. All three come from
`boneli-https`, because ARCHITECTURE keeps ring in that crate only
(ADR-005) and ring already does each of them there.

- **`RsaSha256Key`** signs RSASSA-PKCS1-v1_5 with SHA-256 through rustls'
  public API: `rustls::crypto::ring::default_provider().key_provider`
  loads the key, and `choose_scheme(&[RSA_PKCS1_SHA256])` gives the
  signer. That is ring's RSA, already linked for TLS, so no crate and no
  dependency edge is added. `rs256_known_answer` compares a signature byte
  for byte with OpenSSL's over a JWT signing input (the scheme is
  deterministic), and `pkcs1_and_pkcs8_sign_alike` with the same key in
  both encodings.
- **The key rules** (`from_pem`, pinned by `key_rules`):
  - exactly one PEM section, counted from the `-----BEGIN ` lines
    themselves, because rustls' PEM parser skips sections it does not
    know. Two keys, a key with its certificate, or a certificate alone
    are refused: a file that holds more than one thing is a
    misconfiguration, and picking one of them would hide it;
  - the section is `RSA PRIVATE KEY` (PKCS#1) or `PRIVATE KEY` (PKCS#8).
    An encrypted, SEC1 or OpenSSH key, a public key and a certificate are
    refused with their own error (`UnsupportedSection`);
  - ring must accept the key, which means a consistent RSA key with a
    modulus of 2048 to 4096 bits (ring 0.17's limits for RSA signing
    keys).
    A 1024-bit key is refused (`Rejected`); a P-256 key, which ring
    accepts, is `NotRsa`;
  - the input is at most 16,384 bytes, checked before any parsing
    (`pem_size_cap`). The largest key ring signs with, 4096 bits, is
    about 3,270 bytes of PEM (3,268 and 3,272 in two keys), and 11,125
    bytes with OpenSSL's text dump in front (`openssl pkey -text`,
    measured with OpenSSL 3.5), so a
    key file printed with its parameters still loads. A cap below about
    3,300 bytes would refuse a valid key; a higher one only admits more
    text around the one section. The key file is read once at start
    (part 3), so the cap bounds that read, not a hot path.
- **One signature at load.** `from_pem` signs an empty message before it
  returns the key: a key that cannot sign fails at start, not at the
  first token exchange, and the signature's length is the modulus size,
  which rustls does not expose. It must be 256 to 512 bytes (2048 to 4096
  bits); `sign` checks every later signature against it. The cost is one
  RSA signature per start.
- **Key material stays out of output** (D6 extends this to the forge).
  `Debug` shows `RsaSha256Key { modulus_bits: 2048 }` and nothing else;
  every `KeyError` is a fixed sentence with no source, so no parser
  message can quote key bytes (`debug_has_no_key_material` checks every
  16-byte window of the test keys' base64 against all of them).
- **Wiping, best effort.** `from_pem` takes `&mut [u8]` and fills it with
  zeros before it returns, on success and on every refusal
  (`input_is_wiped`), so the caller's copy of the key file does not stay
  in memory. The DER that rustls decodes is wiped by rustls itself
  (`Zeroizing` around `load_private_key`), and a DER refused for its
  label is wiped here. Not wiped: the base64 copy rustls' PEM parser
  makes while it decodes, and ring's in-memory key, which lives as long
  as the `RsaSha256Key`. The fill uses `std::hint::black_box` against the
  optimizer, without `unsafe` and without a new edge to `zeroize`. That
  is enough for the threat of D6: what reads this process's memory is
  the same uid or root, which can read the key file anyway.
- **The JWT** (built in part 3) has `iat = now - 60` and
  `exp = now + 540`. It tolerates a runner clock up to 60 s ahead of
  GitHub's, so `iat` is not in the future, while `exp` stays within
  GitHub's documented 10-minute maximum (540 + 60 = 600); and a clock up
  to 540 s behind, so `exp` has not passed yet. A larger back-dating
  would push `exp` past GitHub's maximum for a correct clock. One JWT is
  signed per token exchange and never cached or stored.
- **`fill_random`** fills a buffer from the provider's `secure_random`,
  ring's `SystemRandom`, which reads the `getrandom` system call on Linux
  through the `getrandom` crate (ADR-005 lists both); rustls
  draws its handshake randomness from the same source. A failure is
  `RandomFailed`, never a fallback to a weaker source
  (`fill_random_fills`).
- **The `Dial` seam moves here from `boneli-oci`.** `Dial`, `Stream`,
  `TlsDial` and `Timed` move unchanged, with the socket under TLS that
  holds the request's deadline (ADR-009, D10): a TLS read returns only
  once a whole record has arrived, so a peer that drips a record a byte
  at a time would hold a read above TLS open past any deadline set there.
  The forge needs exactly that socket, and a second copy would put the
  same deadline logic under review twice and let the copies drift. The
  forge cannot import it from `boneli-oci`, because an adapter must not
  depend on another adapter (invariant 1). The seam knows nothing of
  registries or forges, so it fits a support crate. ADR-009's decision is
  unchanged; only the crate holding it changes:
  - `boneli-oci` re-exports `Dial`, `Stream` and `TlsDial`, so its
    callers keep their paths, and its registry client uses
    `boneli_https::Timed`, which becomes public (it was crate-private);
  - the `TlsDial` tests move with it and keep their names; `boneli-oci`
    no longer needs `rustls` as a dev-dependency, so the edge
    `boneli-oci -> rustls` leaves `tools/architecture.toml`.

## Consequences

- Every `Git` adapter must implement `push`; `MemoryGit`, `GitCli` and
  the mutants do. The contract's four push clauses bind any future
  adapter, a GitLab one included.
- The `Forge` suite's `run` takes the ticket every call names, because
  only the adapter's test knows which ticket keys its forge can post on;
  `contract::sample_ticket()` serves forges that take any, and a ticket
  with a blank key or title is a fixture violation.
- `RunCommand::OpenPullRequest` and `PullRequest` carry the run's
  citations, all `Verified` by the root-cause gate, so the forge can
  quote them. The replay corpus changes with the command, in both
  processes alike.
- `GitCliConfig` loses `PartialEq` and `Eq` (a trait object cannot be
  compared), and its `Debug` shows `Some(..)` or `None` for the
  credentials.
- A push writes one commit object into the adapter's store; nothing
  reads it there, and the store goes with the adapter's root.
- A branch pushed by a run that then fails to open a pull request stays
  on the remote. Its name carries the run, so a cleanup can find it; the
  cleanup itself is out of scope (#19 plan).
- `boneli-https` grows from a TLS client and a hash into the crate for
  every use of ring: TLS, SHA-256, RS256 and randomness, plus the `Dial`
  seam over its TLS client. A new use of ring goes there too, and ring
  stays out of every other crate's graph.
- `RsaSha256Key::from_pem` wipes the buffer it is given, so a caller that
  needs the PEM afterwards passes a copy.
- `boneli_https::Timed` is public API now; ADR-009's text still calls the
  seam crate-local, and this ADR is where it moved.

## Alternatives considered

- **Push through GitHub's Git Data API** (blobs, trees, commits, refs).
  The forge would have to read `boneli-git-cli`'s diff format, or the
  port would need a "changed files" operation; it costs n + 3 requests
  for n files; and it contradicts the push path ADR-004 D11 and ADR-010
  D4 already decided. It stays the route to GitHub-signed commits later.
- **Push from `DebugTicket`** instead of from the forge adapter. It
  would add a command to the run and change the replay corpus for a step
  that only the forge needs.
- **A push that may fast-forward an existing `boneli/` branch.** A rerun
  could then move a branch that a human already reviewed. Create-only
  costs a nonce in the name and nothing else.
- **Credentials in a git credential helper** or a credential file. A
  helper is a program named by config, which ADR-010 D4 shuts off
  (`credential.helper=` empty); a file is something a later process or a
  snapshot could read.
- **RustCrypto `rsa` for the JWT signature** (D4). `rsa` 0.10.0 with its
  default features resolves 28 crates with itself, 24 of them new to the
  workspace (`crypto-bigint`, `crypto-primes`, `pkcs1`/`pkcs8`/`der`/
  `spki`, `digest`, `sha2`, `signature`, `rand_core` and their helpers;
  counted with `cargo tree` on 2026-11-19), each a new name with edges
  that need records and review (ADR-001). The 0.9 series (0.9.10, 32
  crates with `std` and `sha2`) carries RUSTSEC-2023-0071,
  a timing side channel that leaks the private key and is patched only
  from 0.10. ring is vetted and linked already (ADR-005).
- **`jsonwebtoken`.** It needs `serde`, which `deny.toml` bans.
- **A copy of the `Dial` seam in the forge** (D4). Two copies of the
  deadline-under-TLS socket to review and keep in step, for no gain.
- **A `zeroize` edge from `boneli-https`** for the wipe (D4). `zeroize` is
  in the graph already, under rustls; a direct edge would need its own
  record for a guarantee `black_box` gives on a best-effort basis too,
  and the residuals above (the parser's copy, ring's key) would stay.

## Accept when

Part 3 of #19 adds D5 to D12 and the live test passes on the operator's
private test repository: the pull request's head is a `boneli/` branch
whose parent is the base and which changes exactly the fixed file, both
pushed and fetched with the App's token through `Credentials`; and the
push from the depth-1 store, with the repository's default branch moved
past the base, sends only the new objects (the push's trace2
`write_pack_file/wrote`, recorded here), or this ADR records that
GitHub does not negotiate with a shallow client and what that costs.
