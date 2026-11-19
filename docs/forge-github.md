# GitHub forge: operator guide

`boneli-forge-github` opens Boneli's pull requests and posts its triage
questions on GitHub as a GitHub App (ADR-014). This guide covers the App,
its private key, and the live acceptance test. The design and the reasons
for every rule are in `docs/adr/014-github-forge.md`.

## The GitHub App

Create the App on the account that owns the repositories
(Settings → Developer settings → GitHub Apps → New GitHub App):

- **Repository permissions:** Contents *Read and write*, Pull requests
  *Read and write*, Issues *Read and write*, and Metadata *Read-only*
  (GitHub makes Metadata mandatory). Nothing else, and no account or
  organization permissions. The adapter requests exactly the first three
  for every token and refuses a token that is granted anything more
  (ADR-014, D5).
- **Webhook:** inactive. Boneli does not take intake from GitHub yet.
- **Where it can be installed:** only on this account.
- **Install it** on the repositories Boneli works on, with "Only select
  repositories". A token is scoped to one repository; the adapter refuses
  a token that covers any other.
- **Branch protection** on every default branch Boneli targets: "Require
  a pull request before merging", with the App on no bypass list. The
  adapter has no merge endpoint, but its token has `contents: write`, and
  this rule is what keeps a leaked token from writing to the default
  branch.

From the App's settings page you need:

- the **client id** (`Iv23li...`, or the numeric App id): the JWT issuer;
- the **installation id**: the number at the end of the installation's
  URL (Settings → Applications → Configure);
- the **bot identity** for commits: the name is `<app-slug>[bot]`, and the
  email is `<id>+<app-slug>[bot]@users.noreply.github.com`, where `<id>`
  comes from `gh api '/users/<app-slug>[bot]' --jq .id`.

## The private key

Generate a private key on the App's settings page. GitHub hands out a
2048-bit RSA key in PKCS#1 PEM; the adapter also takes PKCS#8 and 3072 or
4096 bits, never an encrypted key (ADR-014, D4).

Store it outside every repository, as a file that the user running Boneli
owns, readable by that user only:

```sh
install -m 0600 /dev/null "$KEY_FILE"   # an absolute path of your choice
cat downloaded-key.pem > "$KEY_FILE"
```

The adapter refuses the key file unless (ADR-014, D6):

- the path is absolute (`~` is not expanded);
- it is a regular file, not a symlink, a directory or a FIFO;
- the process's uid owns it;
- group and others have no permission bit: mode `0600` or `0400`;
- it is at most 16,384 bytes and holds exactly one PEM key section.

The key is read once, when the adapter starts. It never goes into an
environment variable, a log, an error message or the run store.

## GitHub ticket keys

The forge reads a GitHub ticket's key as `owner/name#N`: the repository
and the issue number. Only a key that names the configured repository
(compared without regard to ASCII case, as GitHub compares names) gets
the `Fixes #N` line, so the merge closes the issue, and only such a
ticket can take a questions comment. A ticket of any other repository
is shown as `Ticket: GitHub` with its key made inert, and posting
questions on it fails before any request (ADR-014, D7). An intake
adapter that reads GitHub issues must hand the forge keys in this form.

## The live acceptance test

CI runs the forge's tests against a fake GitHub. The live test runs the
real git adapter and the real forge against your App and a private test
repository, and it is run by hand: before a change to
`boneli-forge-github`, or to the git adapter's push and credential path,
merges. It is in `crates/boneli-acceptance/tests/github.rs`.

### The test repository

- **Private**, so the test proves that fetch and push are authenticated.
- A `README.md` on the default branch.
- **Two commits at least:** the base the test starts from (`BONELI_GITHUB_BASE`)
  must not be the tip of the default branch, so the push runs with the
  default branch moved past the base, the case ADR-014 D2 measures.
- An **open issue** for the questions comment and the `Fixes` line (the
  target), and a **second open issue** that the test's hostile text
  references with closing keywords (the decoy), which must stay
  untouched.
- Branch protection on the default branch as above, and the App
  installed on this repository only.

### Variables

Every variable is required; a missing one fails the test and names it.

| Variable | Value |
| --- | --- |
| `BONELI_GITHUB_CLIENT_ID` | the App's client id |
| `BONELI_GITHUB_INSTALLATION_ID` | the installation id |
| `BONELI_GITHUB_KEY` | the absolute path of the key file |
| `BONELI_GITHUB_REPO` | the test repository, `owner/name` |
| `BONELI_GITHUB_ISSUE` | the target issue's number |
| `BONELI_GITHUB_DECOY_ISSUE` | the decoy issue's number, another open issue |
| `BONELI_GITHUB_BASE` | a full 40-hex commit on the default branch, with `README.md`, not the tip |
| `BONELI_GITHUB_COMMIT_NAME` | `<app-slug>[bot]` |
| `BONELI_GITHUB_COMMIT_EMAIL` | `<id>+<app-slug>[bot]@users.noreply.github.com` |

### Running it

```sh
cargo test -p boneli-acceptance --test github -- --ignored --nocapture
```

The test:

1. measures a token exchange and the repository object of its own;
2. posts a comment of hostile questions on the target issue (mentions of
   the `ghost` placeholder account, closing keywords before `#D`,
   `owner/repo#D`, `GH-D` and the decoy's issue and pull URLs, markup, CR,
   U+202E) and checks in GitHub's `body_html` that none of it became a
   mention or a link;
3. fetches the base through the git adapter with the App's token, makes a
   one-line change to `README.md`, and opens a pull request through the
   forge whose ticket title, analysis, test and citation quote carry the
   same hostile text (a 70 KB analysis, a title cut to 256 bytes, a
   citation path with a space);
4. checks the result: the head is a `boneli/` branch whose one parent is
   the base and which changes `README.md` only, the base is the default
   branch, the pull request is not a draft, the body is at most 65,536
   bytes, its only issue link is the `Fixes` line, nothing links to the
   decoy, GitHub's closing references (GraphQL
   `closingIssuesReferences`) are exactly the target issue, and the
   decoy's timeline has no cross-reference from the pull request and no
   `connected`, `referenced` or `cross-referenced` event since the test
   started;
5. prints the response sizes (`size ...` lines) and what the push sent
   (`push: pack-objects wrote [...] objects`);
6. cleans up: closes the pull request and deletes the branch and the
   comment, also when an assertion failed.

Record the printed sizes and the push line in ADR-014 (D10 and D2) when
the run is for a change that affects them.
