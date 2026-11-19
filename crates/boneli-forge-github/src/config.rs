//! Configuration values, each checked when it is made (ADR-014, D5 and
//! D7): the repository, the App's client id and base branch names.

use std::fmt;

use boneli_app::RepoUrl;

/// The longest GitHub account name, in bytes (GitHub's sign-up rule).
pub const MAX_OWNER: usize = 39;

/// The longest GitHub repository name, in bytes (GitHub's rule).
pub const MAX_NAME: usize = 100;

/// One repository on github.com, `owner/name`.
///
/// The owner is 1 to [`MAX_OWNER`] bytes of `[A-Za-z0-9-]` that does not
/// start with `-`; the name is 1 to [`MAX_NAME`] bytes of `[A-Za-z0-9._-]`
/// and not `.` or `..`. Both go into URL paths and the git URL unescaped,
/// which this character set allows.
#[derive(Clone, PartialEq, Eq)]
pub struct GitHubRepository {
    owner: String,
    name: String,
}

impl GitHubRepository {
    /// The repository `owner/name`, or `None` for any other form.
    pub fn parse(text: &str) -> Option<GitHubRepository> {
        let (owner, name) = text.split_once('/')?;
        let owner_ok = (1..=MAX_OWNER).contains(&owner.len())
            && owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !owner.starts_with('-');
        let name_ok = (1..=MAX_NAME).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            && name != "."
            && name != "..";
        (owner_ok && name_ok).then(|| GitHubRepository {
            owner: owner.to_owned(),
            name: name.to_owned(),
        })
    }

    /// The owner.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `owner/name`.
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    /// The git URL, always `https://github.com/<owner>/<name>.git`: the
    /// one URL the forge fetches and pushes, and the one the git
    /// credentials answer for.
    pub fn git_url(&self) -> RepoUrl {
        RepoUrl::new(format!(
            "https://github.com/{}/{}.git",
            self.owner, self.name
        ))
    }

    /// Whether `full_name` names this repository. GitHub compares owner and
    /// name without regard to ASCII case.
    pub(crate) fn is(&self, full_name: &str) -> bool {
        full_name.eq_ignore_ascii_case(&self.full_name())
    }
}

impl fmt::Debug for GitHubRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitHubRepository({}/{})", self.owner, self.name)
    }
}

/// The longest client id, in bytes. GitHub's client ids are 20 bytes
/// (`Iv23li...`) and App ids are decimal numbers, which GitHub also takes
/// as the JWT issuer; 64 leaves room for a longer form.
pub const MAX_CLIENT_ID: usize = 64;

/// The App's client id (or numeric App id): the JWT's `iss` claim. 1 to
/// [`MAX_CLIENT_ID`] bytes of `[A-Za-z0-9._-]`, so it needs no escaping in
/// the claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientId(String);

impl ClientId {
    /// The id, or `None` for any other form.
    pub fn parse(text: &str) -> Option<ClientId> {
        let ok = (1..=MAX_CLIENT_ID).contains(&text.len())
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        ok.then(|| ClientId(text.to_owned()))
    }

    /// The id as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The longest base branch name, in bytes: git's limit on one ref
/// component file is 255 bytes (`NAME_MAX`).
pub const MAX_BASE_BRANCH: usize = 255;

/// Why a base branch name (the repository's `default_branch`, or a
/// configured one) is refused, or `None` when it passes. The name goes into
/// the create request as JSON, never into a URL or the body, so the rule
/// is git's `check-ref-format --branch` rather than a narrow set: no
/// control character, space or any of `~^:?*[\`, no `..`, `@{` or `//`,
/// no component that starts with `.`, does not start with `-` or `/`, does
/// not end with `/`, `.` or `.lock`, and is not `@`.
pub fn base_branch_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() || name.len() > MAX_BASE_BRANCH {
        return Some("it is empty or longer than 255 bytes");
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
    {
        return Some("it holds a control character, a space or one of ~^:?*[\\");
    }
    if name.contains("..") || name.contains("@{") || name.contains("//") || name == "@" {
        return Some("it holds .., @{ or //, or is @");
    }
    if name.starts_with('-') || name.starts_with('/') || name.ends_with('/') {
        return Some("it starts with - or /, or ends with /");
    }
    if name.ends_with('.') || name.ends_with(".lock") || name.split('/').any(|c| c.starts_with('.'))
    {
        return Some("a component starts with ., or it ends with . or .lock");
    }
    None
}
