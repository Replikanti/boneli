//! Boneli adapter: the `Forge` port over the GitHub REST API, as a GitHub
//! App (#19, ADR-014).
//!
//! - [`App`] and [`InstallationTokens`]: the App's key, read once from a
//!   file under the ssh client's rules ([`load_key`], D6), signs an RS256
//!   JWT ([`app_jwt`], D4) that is exchanged for an installation token
//!   scoped to one repository with exactly `contents`, `issues` and
//!   `pull_requests` write; the token is checked, cached while more than
//!   [`MARGIN`] seconds of it remain, and refreshed once on a `401` (D5).
//!   [`InstallationTokens::git_authorization`] gives the git adapter its
//!   `Authorization` value (ADR-014, D3), through a bridge in a
//!   composition root.
//! - [`Endpoint`]: the five requests the adapter can make, GET or POST
//!   only, to `api.github.com:443` through the `Dial` seam, under
//!   [`Limits`] (D7, D10); every failure is a status and GitHub's quoted
//!   `message`, never a body or a secret (D9).
//! - [`render`]: the title, the body, the questions comment and the
//!   commit message, with agent and reporter text only in indented code
//!   blocks and never able to form an issue reference or mention, even
//!   read as plain text ([`render::neutralize`], D8). A GitHub ticket's
//!   key is `owner/name#N`; only one of the configured repository gets
//!   `Fixes #N` and a questions comment ([`render::issue_in`], D7).
//! - [`GitHubForge`]: `fetch_base` → `apply` → `push` through the `Git`
//!   port to a new `boneli/` branch ([`branch_name`]), then the pull
//!   request, ready for review; an ambiguous creation is looked up once by
//!   its branch (D1, D9).
#![doc(test(attr(forbid(unsafe_code))))]

mod api;
pub mod base64;
mod config;
mod forge;
mod jwt;
mod key;
pub mod render;
pub mod time;
mod tokens;

pub use api::{
    ACCEPT, API_HOST, API_PORT, API_VERSION, Endpoint, Failure, Limits, MAX_MESSAGE, USER_AGENT,
};
pub use config::{
    ClientId, GitHubRepository, MAX_BASE_BRANCH, MAX_CLIENT_ID, MAX_NAME, MAX_OWNER,
    base_branch_problem,
};
pub use forge::{ConfigError, ForgeConfig, GitHubForge, MAX_SLUG, branch_name, run_slug};
pub use jwt::{BACKDATE, HEADER, JwtError, LIFETIME, app_jwt, claims};
pub use key::{KeyFileError, KeyFileFacts, KeyFileProblem, key_file_problem, load_key};
pub use time::{SystemClock, WallClock};
pub use tokens::{
    App, InstallationTokens, MARGIN, MAX_LIFETIME, MAX_TOKEN, PERMISSIONS, Token, token_problem,
};
