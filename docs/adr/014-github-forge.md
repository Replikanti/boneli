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
  - the section is `RSA PRIVATE KEY` (PKCS#1) or `PRIVATE KEY` (PKCS#8),
    unencrypted. An encrypted key, under the PKCS#8 label `ENCRYPTED
    PRIVATE KEY` or in OpenSSL's traditional form (`RSA PRIVATE KEY`
    with `Proc-Type:` and `DEK-Info:` header lines, from `openssl genrsa
    -traditional -aes128`), a SEC1 or OpenSSH key, a public key and a
    certificate are refused with their own error
    (`UnsupportedSection`). The traditional headers are checked before
    the rustls parser runs, because it would feed them to base64 and
    report corrupt PEM for a file that is only encrypted (review round 1
    of #72);
  - ring must accept the key, which means a consistent RSA key with a
    modulus of 2048, 3072 or 4096 bits. ring 0.17 signs with moduli of
    2048 to 4096 bits (`rsa/keypair.rs`, `from_bits(2048)` and
    `PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS`) and refuses a prime whose
    length is not a multiple of 512 bits
    (`private_modulus_len_not_multiple_of_512_bits`), so a 2304-bit key
    inside that range is refused too. A 1024-bit and a 2304-bit key are
    refused (`Rejected`, `rejected_names_the_accepted_sizes`); a P-256
    key, which ring accepts, is `NotRsa`;
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
  which rustls does not expose. It must be 256 to 512 bytes (ring's 2048
  to 4096 bits, of which it loads 2048, 3072 and 4096); `sign` checks every later signature against it. The cost is one
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

### D5. Installation tokens

`InstallationTokens` exchanges the App's JWT (D4) for an installation
token and caches it; `GitHubForge` and the git credentials bridge
(D3, in a composition root) share one instance. It is built with
`InstallationTokens::open(app, repository, dial, clock, limits)`: the
`Dial` (D4) and the `limits` (D10, `Limits::GITHUB` in production) live
here because the token exchange is the first request on them and the
forge reuses both, so one value configures every request the adapter
makes. `limits` is an argument rather than a constant so that the tests
can shorten the 30 s deadline to provoke a timeout
(`timeout_on_create_looks_up_by_head`, 300 ms); the plan's signature had
no such argument.

- **The request** is `POST /app/installations/{id}/access_tokens` with
  `{"repositories":["<name>"],"permissions":{"contents":"write","issues":"write","pull_requests":"write"}}`.
  A token never covers more than the one repository and the three
  permissions the forge uses, whatever the installation allows.
- **The answer is checked** before the token is used: the permissions
  are exactly the three requested, plus optionally `metadata: read`,
  which GitHub always adds (`permissions_must_equal_request`: an extra
  `administration: write` or a `contents: read` is refused);
  `repository_selection` is `selected`, and `repositories` holds exactly
  one entry whose `full_name` is ours, compared without regard to ASCII
  case as GitHub compares it (`repository_scope_is_checked`). An
  installation that was widened by mistake therefore fails closed instead
  of handing the runner a broader token.
- **The token** is 1 to 4,096 bytes of `0x21`-`0x7E`
  (`token_value_rules`). Today's tokens are 40 characters; 4,096 is 100
  times that, room for a format change, and it is what bounds the git
  `Authorization` value (D3). A lower cap risks refusing a valid future
  token; a higher one only admits larger headers.
- **Reuse margin: 600 s.** A token is reused while more than 600 s of it
  remain, and refreshed at 600 s left (`token_is_cached_until_margin`:
  minted at t0 for an hour, reused at t0+2,999, new at t0+3,000). Why
  600: the runner's clock may be 60 s off GitHub's (D4), and one git
  process takes the value once and may use it for its last request up to
  the 300 s stall bound of a transfer later (`http.lowSpeedTime`, ADR-010
  D4), so 60 + 300 = 360, rounded up. A smaller margin risks a token
  expiring inside a slow push; a larger one costs one more exchange per
  hour at most (at 600 s, one per 50 minutes).
- **Lifetime cap: 3,600 s,** GitHub's documented hour: `expires_at` is
  clamped to the mint time plus an hour, so a clock or an answer that
  claims more cannot extend the cache (`expires_at_beyond_an_hour_is_clamped`).
- **An `expires_at` at most 600 s away is refused**
  (`token_expiring_within_margin_is_refused`): t0+600 is refused, t0+601
  taken. Such a token could not be reused at all.
- **`expires_at`** is an RFC 3339 `date-time` (section 5.6) with `T` or
  `t`, an optional fraction of 1 to 9 digits, and `Z`, `z` or an offset
  that is applied; a leap second, a day the month lacks, a year before
  1970 and a time before the epoch are refused (`expires_at_forms`,
  `rfc3339_round_trips_every_day` over 1970-01-01 to 2100-12-31). The
  civil-date arithmetic is Hinnant's `days_from_civil`.
- **A clock that went back** since the mint forces a new token
  (`clock_going_back_refreshes`): the cache cannot tell how much of the
  token is left.
- **A `401`** on any request made with the token drops the cached token if
  it is still the refused one, and the request is sent once more with a
  new token (`unauthorized_refreshes_once`: 401 twice is exactly two
  exchanges and a failure). A `401` on the exchange itself is not
  retried: a refused JWT does not get better on a second try.
- **Concurrency.** The cache's lock is held through an exchange, so
  callers that need a token at the same time wait for one exchange and
  share its token (`concurrent_callers_share_one_exchange`). An exchange
  is bounded by the request deadline (D10).
- **The wall clock** is a seam (`WallClock`, `SystemClock`); the core has
  no clock (invariant 2), this adapter needs one because a JWT and a
  token carry absolute times.

### D6. The private key file

The App key is read once, at start, from a file path (`App::open`,
`load_key`); never from an environment variable, which every child
process would inherit. The file must be an absolute path to a regular
file, not a symlink, owned by the process's uid (the owner of
`/proc/self`), with no permission bit for group or others
(`mode & 0o077 == 0`: `0600` and `0400` pass, `0640` does not). That is
the ssh client's rule for private keys, and for the same reason:
disclosure is the threat. Replacement is not, because a swapped key only
signs JWTs that GitHub refuses, so no ancestor directory is checked (unlike
ADR-012's store root, where a swapped log is the threat). The file is
inspected with `lstat`, opened, and its `fstat` must name the same device
and inode and pass the rules again, so a file swapped between the two is
`Replaced`; a FIFO is refused by `lstat` before an open could block on
it. At most 16,384 bytes are read (D4's cap), and the buffer is wiped on
every path (`key_file_rules`; the owner rule is tested on synthetic
metadata, because no test user can own a file as another uid). No error,
`Debug` output or failure detail carries key bytes; the tests check every
16-byte window of the test key's base64 against them.

### D7. Endpoints

The adapter can make five requests, a closed enum (`Endpoint`), and
nothing else:

| Endpoint | Auth | For |
| --- | --- | --- |
| `POST /app/installations/{id}/access_tokens` | JWT | a token (D5) |
| `GET /repos/{o}/{r}` | token | `default_branch`, when no base branch is configured |
| `POST /repos/{o}/{r}/pulls` | token | the pull request |
| `GET /repos/{o}/{r}/pulls?head={o}:{branch}&state=all&per_page=2` | token | the lookup of an ambiguous creation (D9) |
| `POST /repos/{o}/{r}/issues/{n}/comments` | token | the questions comment |

There is no merge, `PATCH`, `PUT` or `DELETE`, so the adapter cannot
merge, edit or delete anything (`endpoints_are_a_closed_set`). Every value
in a target comes from a checked type (the repository, D2's
`BranchName`, a number) whose characters need no percent-encoding. Every
request sends `Accept: application/vnd.github+json`,
`X-GitHub-Api-Version: 2022-11-28`, `User-Agent: boneli-forge-github` and
`Authorization: Bearer <jwt or token>`, and `Content-Type:
application/json` with a body (`token_request_is_scoped`,
`pull_request_request_is_exact`). A pull request is created with
`"draft": false`, ready for review (STOP 1 decision 4: draft pull
requests fail on private repositories of plans without them, and a human
merges anyway). The head is the bare branch name, which GitHub reads in
the repository itself.

`GitHubForge::new(tokens, git, config)` takes a `ForgeConfig`: the
commit's author name and email (the App's bot identity), checked at
construction under `CommitInfo`'s rules (D2), so a misconfigured identity
fails at start instead of at the first push; and an optional base branch.
`open_pull_request` composes `fetch_base` → `apply` → `push` through the
`Git` port (D1) between reading the base branch and creating the pull
request. The base branch is the configured one or the repository's
`default_branch`, checked against `git check-ref-format --branch`'s rules
and at most 255 bytes (`default_branch_rules`); it goes into the request
as JSON only.

**GitHub ticket keys are `owner/name#N`.** `Ticket` carries no
repository, so the key carries it: the repository under GitHub's name
rules (the owner 1 to 39 bytes of `[A-Za-z0-9-]` not starting with `-`,
the name 1 to 100 bytes of `[A-Za-z0-9._-]`, so a confusable or
non-ASCII owner is refused) and the issue number `[1-9][0-9]*` up to
`u64::MAX`. The ticket is "of the same repository" (STOP 1 decision 3)
when that repository equals the configured one, compared without regard
to ASCII case as GitHub compares names. Only then does the body carry
`Fixes #N` (D8) and may `post_questions` comment; a ticket of any other
repository (another tracker repository, a fork) gets neither, and
`post_questions` fails before any request, as it does for another
tracker's ticket or an empty list (`github_issue_key_forms`: a mismatch,
a case-only difference, a Cyrillic and a fullwidth owner;
`no_questions_no_comment`). A bare number is refused: it cannot say which
repository it means, and guessing the configured one is how a ticket of
`org/tracker#12` would close or comment on `org/app#12`. No domain change
is needed; an intake adapter for GitHub must produce this form.

**References are `pull/<number>` and `comment/<id>`**, from GitHub's
`number` and `id` (`reference_comes_from_number`), each a JSON integer
from 1 to `u64::MAX`: `0`, `-1`, `1.0`, `1e3`, `"42"` and `u64::MAX + 1`
are refused (`number_forms`). Why a kind prefix and not the bare number:
pull-request numbers and comment ids are separate number spaces on
GitHub (numbers count per repository, comment ids globally), so a bare
`5` could name either, and the `Forge` contract's `distinct-references`
clause would fail the day a pull request and a comment share a number.
The prefix also tells a later reader of the run log (retries in #33, the
transcript link in #20) which endpoint the reference belongs to.

### D8. Rendering: agent text stays inert

The title, the body, the comment and the commit message are rendered by
the adapter (`render`), because the format depends on the forge (ADR-004).

- **The inert rule.** Outside code blocks there is only text the adapter
  generates from validated values: numbers, enum labels, SHAs inside
  URLs, and keys, run ids and evidence references of 1 to 64 (keys) or
  128 bytes of `[A-Za-z0-9._-]`, in inline code; a value outside that set
  is left out and a generated phrase says so. Agent and reporter text (the
  analysis, the reproduction test, citation paths and quotes, the
  questions) goes into **indented code blocks**, where GitHub's Markdown
  creates no mention, no issue reference, no closing keyword and no
  markup. Indented, not fenced: a fence can be closed by the text inside
  it (a longer fence, `~~~`), an indented block only by a line the adapter
  writes. Every block follows a blank line and is followed by one, and no
  list item is ever open before one, because an indented line after a
  list item continues the item instead of starting code
  (`hostile_text_stays_in_code_blocks` runs a CommonMark block scanner
  over the output: mentions, `@org/team`, `#1`, `Closes #1`,
  `owner/repo#1`, fences, `</pre>`, HTML, links, task lists, quotes and
  table rows appear only on code lines).
- **No references in free text, even outside Markdown** (review round 1
  of #73). A code block is inert only where GitHub renders Markdown. The
  title is plain text, GitHub's default squash and merge commit messages
  carry the pull request's title (and, with the repository setting "pull
  request title and description", its body) verbatim, and GitHub reads a
  commit message on the default branch as plain text for closing keywords
  and references, across repositories the merger can write to. So every
  piece of reporter or agent text (the title, every code block: the
  analysis, the test, the questions, citation paths and quotes; and the
  ticket keys, run ids and evidence references shown) also passes through
  `neutralize`, which breaks every reference form visibly: `#` becomes the
  fullwidth `＃` (U+FF03) and `@` the fullwidth `＠` (U+FF20), so no `#N`,
  `owner/repo#N`, `@user` or `@org/team` can form; the dot of
  `github.com` (any case) becomes U+2024 `․`, so no issue or pull URL
  can form; and the hyphen of `GH-` (any case) before a digit becomes
  U+2011 `‑`, so no `GH-N` can form. A closing keyword (close, closes,
  closed, fix, fixes, fixed, resolve, resolves, resolved, in any case,
  with or without a colon) closes only through a reference that follows
  it, so with every reference broken it is plain prose, and it is left as
  written: rewriting the words would garble ordinary text ("this fixes
  the parser") and protect nothing more. Why visible substitutes and not
  a zero-width joiner or an escape: an invisible character is exactly
  what the escape rule shows as `\u{XXXX}`, and a reader should see that
  the text was changed; the fullwidth forms read as the original.
  **The reader is told.** U+2024 and U+2011 look like `.` and `-`, so a
  quoted line (a Go `import "github.com/x/y"`) would look verbatim and
  not be found by a search (review round 2 of #73). The intro of every
  body and comment therefore names each substitution with its
  replacement and code point, `` `#` as `＃` (U+FF03), `@` as `＠`
  (U+FF20), `.` in `github.com` as `․` (U+2024), `-` in `GH-` before a
  digit as `‑` (U+2011) ``, and says to undo them before searching. The
  function and the note read the same table, `render::SUBSTITUTIONS`
  (`reader_note_lists_every_substitution`: every entry is in the note,
  and every character `neutralize` introduces over all printable ASCII
  and every trigger is in the table).
  The citation permalink is generated, but its path is the agent's, so
  the same two dots and hyphens are percent-encoded there too (`#` and
  `@` are encoded anyway); the link still resolves to the same path.
  Measured on 2026-11-19 against github.com, on this repository's public
  commit `25b0800`: `blob/25b0800/crates/boneli%2Dhttps/Cargo%2Etoml`
  answered HTTP 200 and the page's resolved `"path"` was
  `crates/boneli-https/Cargo.toml`; lower-case `%2d`/`%2e` also answered
  200; a path that does not exist answered 404 encoded and unencoded
  alike (`curl` status plus the resolved path in the page). Assumed, not
  measured: private repositories go through the same web routing, so
  their permalinks decode alike.
  `references_never_form_in_free_text` checks all nine keywords in three
  cases, with and without a colon, before `#5`, `owner/repo#5`, another
  repository's `#5`, `GH-5`, `gh-5`, issue and pull URLs (`http`, `www`,
  upper case) and the two mentions, in the title, in each code block of
  the body and in the comment, with a plain-text detector that also
  reads the generated parts; the only reference left in a body is the
  generated `Fixes #N` line. The live test checks GitHub's own view
  (D12).
- **Escaping.** Before it is indented, every character that is Cc except
  LF and TAB, U+2028, U+2029 or `Default_Ignorable_Code_Point` (the
  domain's table, now public) becomes the text `\u{XXXX}` (`escape_rule`).
  CR is Cc, so a lone CR cannot end a line inside the block; U+202E and
  zero-width characters cannot hide text. The title escapes LF and TAB
  too.
- **Invalid UTF-8** in the analysis or the test is shown lossily (U+FFFD)
  under a generated note (`non_utf8_is_shown_lossily_with_note`).
- **The ticket line.** For a GitHub ticket `owner/name#N` of the
  configured repository (D7; the number `[1-9][0-9]*` up to `u64::MAX`, so
  `0`, `0123`, `+1`, fullwidth digits, `12 ` and `1` before U+00A0 are
  not), the body starts with `Fixes #N`, so the human's merge closes the
  issue (STOP 1 decision 3). Any other ticket gets
  `Ticket: <Source> \`<key>\`` with the key neutralized
  (`octo-org/tracker＃12`, `GH‑12`), or the source alone when the key is
  outside its safe form (`fixes_line_only_for_github_ticket`). An empty
  analysis or test shows a generated `(empty)`.
- **Layout:** the ticket line, a generated intro, the root cause (each
  citation as a permalink
  `https://github.com/<o>/<r>/blob/<base>/<path>#L<line>` with every path
  byte outside `[A-Za-z0-9._~/-]` percent-encoded, then `path:line` and
  the quote as code; `citation_permalinks`; a link longer than 1,024 bytes
  is left out and the path still shows as code. Why 1,024: the fixed
  part of a permalink is at most about 240 bytes (`https://github.com/`,
  a 39-byte owner, a 100-byte name, `/blob/`, a 64-hex SHA, `#L` and ten
  digits), and 1,024 leaves 780 bytes for the path, a 260-byte path fully
  percent-encoded; 260 is Windows' classic `MAX_PATH`, which repositories
  with Windows contributors keep their paths under. A longer cap would
  let one link, which is placed whole or not at all, take a larger part
  of the citations block's share; a shorter one would drop links to
  ordinary deep paths), the analysis, the
  reproduction test, a results table (before the fix the reproduction
  gate's "fails on an assertion"; with the fix every `TestStatus` and
  `CheckStatus` through an exhaustive match, `every_status_has_a_distinct_label`),
  the cost as `$<µUSD / 10^6>.<6 digits>` and the job time as
  `<s>.<ms> s`, the overrun statement of ADR-002 D3 when there is one, a
  saturated total reading "at least" (`cost_and_overrun_render_exactly`,
  `saturated_overrun_says_at_least`), and a footer with the run id, the
  evidence references and "a human reviews and merges".
- **Title:** `Fix: <ticket title>`, escaped and neutralized, at most 256 bytes; a longer
  one is cut at a char boundary to 253 bytes plus `…`
  (`title_cap_arithmetic`: 251 ASCII bytes give 256, 252 give `Fix: ` + 248
  + `…`, 85 × `€` give 254). 256 is GitHub's title limit.
- **Commit message:** `boneli: fix for <Source> ticket <key>`, a blank
  line and `Run <id>`, generated, with no closing keyword and the key and
  id neutralized (`octo-org/demo.repo＃7`), so the commit closes and
  references nothing on its own.
- **Caps.** A body or comment is at most 65,536 bytes, GitHub's documented
  limit of 65,536 characters: bytes are at least as many as UTF-16 units
  and as scalar values, so the cap holds however GitHub counts. The live
  test sends a body cut to the cap and a 256-byte title (D12).
- **Sharing the space.** The generated parts take at most 4,096 bytes
  (`fixed_parts_bound`, measured with every id at its longest, both UTF-8
  notes and a saturated overrun: about 2.2 KB). The rest is water-filled
  over the blocks (citations, analysis, test; or the questions): each
  block, smallest need first, gets the smaller of its need and an equal
  share of what is left, so what a small block leaves passes on to the
  larger ones (`body_cap_arithmetic`: 60,000 bytes over needs 2,000,
  50,000 and 30,000 give 2,000, 29,000 and 29,000; a body whose needs fit
  exactly is 65,536 bytes, and one byte more cuts exactly one block). A
  cut block ends with a generated marker that names the evidence
  reference holding the full text.
- **Questions.** A comment shows at most 64 questions, each under its own
  heading; a generated line counts the rest. 64 keeps the headings inside
  the 4,096 fixed bytes and leaves each question at least 960 bytes
  (`questions_comment_caps_at_65536_bytes`).
- **Transcript link.** `PullRequest` carries no transcript reference, so
  the link waits for #20.

### D9. Errors and rate limits

- **Every failure** is a `JobFailure` with cost 0, whose status is
  `<what>: GitHub answered <code>` plus ` (request <id>)` when
  `x-github-request-id` is 1 to 64 bytes of `[A-Za-z0-9:]`, and whose
  error output is GitHub's `message`, at most 256 bytes cut at a char
  boundary and quoted with Rust's `{:?}` escaping, so a control character
  in it cannot forge a line (`status_mapping_table`). 256: the longest
  common message, the secondary rate limit's, is about 170 characters.
  A failure never carries a response body, a request header, a token, a
  JWT or key bytes: the `Authorization` value of the request is redacted
  where the failure is built, and a final pass redacts the 16 most recent
  tokens and JWTs before it leaves the adapter
  (`failure_details_never_carry_secrets`: a server that echoes the
  `Authorization` value in `message` for every endpoint and status).
  `Debug` of the adapter's types shows no token and no key
  (`debug_output_redacts`).
- **`3xx` is a failure;** no redirect is followed, so a token can never
  follow one to another host.
- **A rate limit** is a 403 or 429 with `x-ratelimit-remaining: 0` or a
  `retry-after`. It is reported with the retry delay or the reset time and
  never retried (`rate_limit_is_reported_not_retried`). Why no retry: one
  run makes at most four REST requests (token, repository, pull request,
  lookup), and GitHub's documented limits are at least 5,000 requests per
  hour per installation, and 80 per minute and 500 per hour for content
  creation. Even the content limit allows 500 pull requests or comments
  per hour against "dozens of runs per runner" (ARCHITECTURE), so a rate
  limit means a fault, not load, and retries belong to #33.
- **An ambiguous creation** is a 5xx, a network error, a deadline, or a
  2xx that is not a `201` with a usable `number`. GitHub may have created
  the pull request, so the adapter looks it up once by its head branch,
  which is unique per call (D2's nonce): exactly one pull request found
  is success; none or two, or a failed lookup, is a failure that carries
  both errors (`ambiguous_creation_looks_up_by_head`,
  `timeout_on_create_looks_up_by_head`). Every other answer (a 4xx, a
  rate limit) is a plain failure: GitHub did not create anything.

### D10. Limits

Measured on 2026-11-19 on public REST objects: a repository object is
7,171 B with 164 values and depth 4; a pull request 26,679 B and 361
values with a 9,856 B body; a large public pull request 20,709 B and 468
values with a 186 B body; a comment 2,562 B and 44 values; response heads
1,448 to 1,493 B in 28 or 29 lines. The limits (`Limits::GITHUB`,
`response_limits` at each boundary and one past it):

- **Body: at most 1,048,576 B.** The pull request's answer echoes its
  body, and GitHub's JSON encoder writes `<`, `>` and `&` as `\u003c` and
  the like, six bytes for one, so the worst echo of a 65,536-byte body is
  6 × 65,536 = 393,216 B.
  With the measured non-body part, about 20,709 B, the lookup's two pull
  requests need 2 × 413,925 = 827,850 B ≤ 1,048,576. A lower cap could
  turn a successful creation into a failure.
- **Depth: at most 16,** 3.2 times the measured 5 (the lookup's array
  around a pull request).
- **Values: at most 4,096,** 4.4 times the 936 values of two pull
  requests; at about 136 B per value (ADR-008) that is about 557 KB of
  memory.
- **Head: at most 16,384 B and 64 fields,** 11 and 2.2 times the measured
  heads.
- **Deadline: 30 s per request,** GitHub's documented 10 s processing cap
  plus connect, TLS and transfer, through the `Timed` socket under TLS
  (D4). The JSON is parsed with `boneli-json` under these limits; a
  duplicate key, a BOM, trailing bytes or invalid UTF-8 fail
  (`malformed_json_refused`).

### D11. Network

The adapter talks to `api.github.com:443` directly through `TlsDial`, with
Mozilla's roots (ADR-005), not through `boneli-egress`: the egress proxy
is the sandbox's broker and its log is the sandbox's evidence, while the
adapter runs in the runner, the trusted side. That is why the egress
proxy (#10) is no dependency of this one. Only github.com is supported;
GitHub Enterprise Server and HTTP proxies in customer networks are a
follow-up, like #55.

### D12. Acceptance

CI runs everything against fakes: a fake GitHub over `UnixStream::pair`
through the `Dial` seam (every test above), a `Git` double for the forge,
and `file://` remotes for the git adapter's push (D1 to D3). The
`Forge` contract suite runs on `GitHubForge`
(`github_forge_passes_contract`; `silent-failure-detail` with every answer
a 503 with an empty body).

The live test, `opens_a_pull_request_on_the_test_repository` in the
test-only composition root `boneli-acceptance`, runs the real `GitCli`
and `GitHubForge` against the operator's GitHub App and private test
repository (setup and variables: `docs/forge-github.md`). It is
`#[ignore]`d, run by hand before a change to the forge or to the git push
and credential path merges (STOP 1 decision 2: no scheduled workflow and
no App key in this repository's secrets), and a missing variable fails it,
naming the variable; it never skips. It posts hostile questions, opens a
pull request from a one-file fix with a 70 KB hostile analysis, a 256-byte
title and a citation path with a space, checks the branch, its parent,
the changed file, the base and the absence of mention and issue-link
anchors in `body_html` (only the `Fixes` line may link), prints the
response sizes and what the push sent, and cleans up. Because anchors are
only GitHub's rendering, the test also checks GitHub's own linkage
(review round 1 of #73): a second open issue, the decoy
(`BONELI_GITHUB_DECOY_ISSUE`), is referenced after closing keywords as
`#D`, `owner/repo#D`, `GH-D` and its issue and pull URLs in the ticket
title, the questions and every block of agent text. The pull request's
`closingIssuesReferences` (GraphQL) must be exactly the target issue, no
anchor may point at the decoy, and the decoy's whole timeline (GraphQL
`timelineItems`, every page) must hold no `ConnectedEvent`,
`CrossReferencedEvent` or `ReferencedEvent` whose pull request is the
test's (by node id), whose source is the target issue (the questions
comment is posted there), or whose commit is the pushed one; events are
identified by those ids, not by the runner's clock, and the same query
on the target issue must find the pull request's link, a positive
control that the query sees links at all (review round 2 of #73). Before
anything is created, both issues must be open issues, not pull requests,
and different, or the test fails naming the variable
(`issues: write` covers reading them). A target issue numbered like a
hostile reference can no longer make the anchor check pass vacuously,
since the decoy is a different issue the test names.

`boneli-acceptance` is the one crate that wires `boneli-git-cli` and
`boneli-forge-github` together: an adapter must not depend on another
(invariant 1), and the architecture check skips dev-dependencies, so the
root declares both as regular dependencies and holds a `roles.roots`
entry. The bridge that gives the git adapter the forge's tokens
(`Credentials` from `InstallationTokens::git_authorization`, for the
repository's own URL only) lives in the test; the runner's root (#32)
gets the same ten lines.

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
- `boneli-forge-github` holds the App key, mints tokens with
  `contents: write` and renders agent text into pull requests, so it is
  on the list of crates that always get an adversarial review (STOP 1
  decision 1).
- A forge call can block for up to the request deadline (D10) per
  request, and a caller waiting for a token waits for one exchange.
- The base branch is the default branch or a configured one; a base
  commit outside that branch's history shows extra commits in the pull
  request. Revoking tokens after use, cleaning up stale `boneli/*`
  branches, retries (#33), GitHub Enterprise Server and the transcript
  link (#20) are out of scope.
- A GitHub ticket's key is `owner/name#N` (D7); an intake adapter for
  GitHub must produce that form, or its tickets get no `Fixes` line and
  no questions comment.
- Reporter and agent text on GitHub shows `＃`, `＠`, `github․com` and
  `GH‑N` where the original had `#`, `@`, `github.com` and `GH-N` (D8).
- `own_uid` is now in three crates (`boneli-oci`, `boneli-store-fs`, this
  one); #66's extraction should take this copy too.

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
- **Fenced code blocks** for agent text (D8). A fence is closed by any
  longer fence or `~~~` line inside the text, so the text would need
  rewriting; an indented block ends only at a line the adapter writes.
- **Retrying a rate limit or a 5xx** in the adapter (D9). One run makes
  four requests; a retry policy belongs to the job layer (#33), which
  sees the whole run.
- **The App key in an environment variable** (D6). Every child process,
  git included, would inherit it.

## Accept when

The live test (D12) passes on the operator's private test repository,
run once before this ADR's PR merges, and its output settles the two
items still open:

- **Pending: measured live sizes (D10).** The token, repository, comment,
  pull-request and lookup answers the live test prints (`size ...`) are
  within D10's limits and are recorded here.
- **Pending: shallow negotiation (D2).** With the default branch moved
  past the base, the push from the depth-1 store sends only the new
  objects (the push's trace2 `write_pack_file/wrote`, printed as
  `push: pack-objects wrote [...]`, recorded here), or this ADR records
  that GitHub does not negotiate with a shallow client and what that
  costs.

The rest of the check is the test's own assertions: the pull request's
head is a `boneli/` branch whose one parent is the base and which changes
exactly the fixed file, fetched and pushed with the App's token through
`Credentials`; the body is at most 65,536 bytes, the title 256; and
GitHub's `body_html` of the pull request and the comment holds no mention
and no issue link but the `Fixes` line; the pull request's closing
references are exactly the target issue; and the decoy issue gets no
link, no closing reference and no timeline event.
