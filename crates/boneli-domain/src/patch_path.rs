//! Path classes of the patch policy (ADR-013, D4 and D7).
//!
//! Every class is matched on folded path components ([`fold_component`]),
//! so a name that is a forbidden one on some file system is refused here
//! too. Folding over-matches on purpose: it can only refuse names no fix
//! needs (the reasoning of ADR-010, D6).

use alloc::string::String;

use crate::values::is_default_ignorable;

/// A class of paths a fix must not touch (ADR-013, D4), in matching order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ForbiddenClass {
    /// A `.git` component, or its 8.3 short name `git~N`.
    RepositoryMetadata,
    /// CI configuration: a `.github` or `.gitlab` directory, the other CI
    /// systems' directories and files.
    Ci,
    /// Dockerfiles, Containerfiles, their ignore files and compose files.
    ContainerBuild,
    /// `CODEOWNERS` in any directory.
    CodeOwners,
    /// `.gitattributes` and `.gitmodules`.
    GitConfig,
    /// Package manifests, lockfiles and package manager configuration.
    Dependencies,
}

/// One path component as a case-insensitive, normalizing or Windows file
/// system may see it: cut at the first `:` (NTFS stream syntax), without
/// Unicode default-ignorable code points, with the non-ASCII code points
/// whose case mapping or case folding is ASCII letters replaced by those
/// letters, ASCII lowercased, and trailing `.` and ` ` trimmed.
///
/// The code points: the simple case mappings of UnicodeData.txt, U+0130
/// and U+0131 to `i`, U+017F to `s` and U+212A to `k`, and the full case
/// foldings of CaseFolding.txt (Unicode 18.0.0), which casefolding file
/// systems apply: U+00DF, U+1E9E and U+1DF95 to `ss`, U+FB00 to U+FB06 to
/// `ff`, `fi`, `fl`, `ffi`, `ffl`, `st` and `st`. No other code point maps
/// to an ASCII letter in either file (ADR-013, D4 records the method).
pub fn fold_component(component: &str) -> String {
    let cut = component.split(':').next().unwrap_or("");
    let mut out = String::with_capacity(cut.len());
    for c in cut.chars() {
        if is_default_ignorable(c) {
            continue;
        }
        let folded = match c {
            '\u{130}' | '\u{131}' => "i",
            '\u{17F}' => "s",
            '\u{212A}' => "k",
            '\u{DF}' | '\u{1E9E}' | '\u{1DF95}' => "ss",
            '\u{FB00}' => "ff",
            '\u{FB01}' => "fi",
            '\u{FB02}' => "fl",
            '\u{FB03}' => "ffi",
            '\u{FB04}' => "ffl",
            '\u{FB05}' | '\u{FB06}' => "st",
            _ => {
                out.push(c.to_ascii_lowercase());
                continue;
            }
        };
        out.push_str(folded);
    }
    let kept = out.trim_end_matches(['.', ' ']).len();
    out.truncate(kept);
    out
}

/// The key under which a component aliases another on some file system,
/// for links (ADR-013, D6): the folded component when it is ASCII, and one
/// shared key for every component that is not. The domain has no Unicode
/// case folding or normalization tables, so a non-ASCII component is taken
/// to alias every other non-ASCII component (`Ä` and `ä`, `é` and `e` with
/// U+0301), which refuses too much rather than too little.
pub fn alias_key(component: &str) -> String {
    let folded = fold_component(component);
    if folded.is_ascii() {
        folded
    } else {
        String::from("\u{FFFD}")
    }
}

const CI_DIRECTORIES: [&str; 6] = [
    ".github",
    ".gitlab",
    ".circleci",
    ".buildkite",
    ".azure-pipelines",
    ".woodpecker",
];

const CI_FILES: [&str; 14] = [
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    ".travis.yml",
    "jenkinsfile",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "bitbucket-pipelines.yml",
    ".drone.yml",
    ".drone.yaml",
    ".woodpecker.yml",
    ".woodpecker.yaml",
    "appveyor.yml",
    ".appveyor.yml",
    ".cirrus.yml",
];

const DEPENDENCY_FILES: [&str; 12] = [
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    ".yarnrc",
    ".yarnrc.yml",
    ".npmrc",
    ".pnpmfile.cjs",
    "bun.lock",
    "bun.lockb",
];

fn is_short_git(name: &str) -> bool {
    name.strip_prefix("git~")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn is_container_build(name: &str) -> bool {
    let yaml = name.ends_with(".yml") || name.ends_with(".yaml");
    matches!(
        name,
        "dockerfile" | "containerfile" | ".dockerignore" | ".containerignore"
    ) || name.starts_with("dockerfile.")
        || name.starts_with("containerfile.")
        || name.ends_with(".dockerfile")
        || name.ends_with(".containerfile")
        || (yaml && (name.starts_with("compose.") || name.starts_with("docker-compose.")))
}

/// The first forbidden class of a path, in [`ForbiddenClass`] order, or
/// `None`. The path is split at `/`; every component is folded.
pub fn forbidden_class(path: &str) -> Option<ForbiddenClass> {
    let mut any_metadata = false;
    let mut any_ci = false;
    let mut any_yarn = false;
    let mut last = String::new();
    for component in path.split('/') {
        let folded = fold_component(component);
        any_metadata |= folded == ".git" || is_short_git(&folded);
        any_ci |= CI_DIRECTORIES.contains(&folded.as_str());
        any_yarn |= folded == ".yarn";
        last = folded;
    }
    let name = last.as_str();
    if any_metadata {
        Some(ForbiddenClass::RepositoryMetadata)
    } else if any_ci || CI_FILES.contains(&name) || name.starts_with("jenkinsfile.") {
        Some(ForbiddenClass::Ci)
    } else if is_container_build(name) {
        Some(ForbiddenClass::ContainerBuild)
    } else if name == "codeowners" {
        Some(ForbiddenClass::CodeOwners)
    } else if name == ".gitattributes" || name == ".gitmodules" {
        Some(ForbiddenClass::GitConfig)
    } else if any_yarn || DEPENDENCY_FILES.contains(&name) {
        Some(ForbiddenClass::Dependencies)
    } else {
        None
    }
}

fn last_folded(path: &str) -> String {
    fold_component(path.rsplit('/').next().unwrap_or(""))
}

const JS_TS_EXTENSIONS: [&str; 8] = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"];

const TEST_DIRECTORIES: [&str; 8] = [
    "__tests__",
    "test",
    "tests",
    "e2e",
    "spec",
    "specs",
    "playwright",
    "cypress",
];

const TEST_STEM_SUFFIXES: [&str; 8] = [
    ".test", ".spec", "-spec", "_spec", ".e2e", ".cy", "-test", "_test",
];

/// Whether the path is a JavaScript or TypeScript file by its folded last
/// component (ADR-013, D7).
pub fn is_js_ts(path: &str) -> bool {
    let name = last_folded(path);
    JS_TS_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
}

/// Whether the path is a JS/TS test file: a JS/TS file in a test directory
/// (any folded directory component), or whose stem, the folded name
/// without its last extension, ends in a test suffix (ADR-013, D7).
pub fn is_test_file(path: &str) -> bool {
    if !is_js_ts(path) {
        return false;
    }
    let mut components = path.split('/');
    let name = components
        .next_back()
        .map(fold_component)
        .unwrap_or_default();
    let in_test_directory =
        components.any(|dir| TEST_DIRECTORIES.contains(&fold_component(dir).as_str()));
    let stem = name
        .rsplit_once('.')
        .map_or(name.as_str(), |(stem, _)| stem);
    in_test_directory
        || TEST_STEM_SUFFIXES
            .iter()
            .any(|suffix| stem.ends_with(suffix))
}

/// Whether a path is a test path for links (ADR-013, D6 and D7): a JS/TS
/// test file, or any path with a folded component that names a test
/// directory, the link's own name included (`tests -> shared`).
pub fn is_test_path(path: &str) -> bool {
    is_test_file(path)
        || path
            .split('/')
            .any(|c| TEST_DIRECTORIES.contains(&fold_component(c).as_str()))
}

const TEST_CONFIG_PREFIXES: [&str; 7] = [
    "jest.config.",
    "vitest.config.",
    "vitest.workspace.",
    "playwright.config.",
    "cypress.config.",
    "karma.conf.",
    ".mocharc",
];

/// Whether a change of the path is a change of a JS/TS test runner's
/// configuration (ADR-013, D7). `vite.config.*` counts only when
/// `has_test_key` says that either side configures Vitest in it.
pub fn is_test_config(path: &str, has_test_key: impl FnOnce() -> bool) -> bool {
    let name = last_folded(path);
    TEST_CONFIG_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || (name.starts_with("vite.config.") && has_test_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_component_cases() {
        for (raw, folded) in [
            (".GitHub", ".github"),
            (".github.", ".github"),
            (".github .. ", ".github"),
            (".git\u{200B}hub", ".github"),
            (".github\u{202E}", ".github"),
            ("Docker\u{FEFF}file", "dockerfile"),
            ("CODEOWNER\u{17F}", "codeowners"),
            ("DOC\u{212A}ERFILE", "dockerfile"),
            (".g\u{131}thub", ".github"),
            (".G\u{130}THUB", ".github"),
            ("Docker\u{FB01}le", "dockerfile"),
            // Every full case folding of D4, one entry each (review round 1).
            ("\u{DF}", "ss"),
            ("\u{1E9E}", "ss"),
            ("\u{1DF95}", "ss"),
            ("\u{FB00}", "ff"),
            ("\u{FB02}", "fl"),
            ("\u{FB03}", "ffi"),
            ("\u{FB04}", "ffl"),
            ("\u{FB05}", "st"),
            ("\u{FB06}", "st"),
            ("Dockerfile:x", "dockerfile"),
            (".git::$INDEX_ALLOCATION", ".git"),
            (":x", ""),
            ("...", ""),
            (".githu\u{42C}", ".githu\u{42C}"),
            ("\u{FF24}ockerfile", "\u{FF24}ockerfile"),
        ] {
            assert_eq!(fold_component(raw), folded, "{raw:?}");
        }
    }

    #[test]
    fn alias_keys() {
        assert_eq!(alias_key("Docs."), "docs");
        assert_eq!(alias_key("\u{C4}"), alias_key("\u{E4}"));
        assert_eq!(alias_key("caf\u{E9}"), alias_key("cafe\u{301}"));
        assert_eq!(alias_key("\u{212A}"), "k");
        assert_ne!(alias_key("a"), alias_key("\u{E4}"));
    }

    #[test]
    fn js_ts_and_test_files() {
        for path in [
            "a.js", "b/c.TSX", "x.mjs", "x.cjs", "x.mts", "x.cts", "x.jsx",
        ] {
            assert!(is_js_ts(path), "{path}");
        }
        for path in ["a.vue", "a.py", "a.json", "a.ts.orig", "ts"] {
            assert!(!is_js_ts(path), "{path}");
        }
        for path in [
            "a.test.ts",
            "src/a.spec.js",
            "__tests__/x.ts",
            "e2e/a.ts",
            "x.e2e-spec.ts",
            "x.cy.ts",
            "x_test.js",
            "Test/x.ts",
            "apps/web/playwright/login.ts",
            "a.TEST.TS",
        ] {
            assert!(is_test_file(path), "{path}");
        }
        for path in [
            "src/a.ts",
            "tests/a.py",
            "test.ts",
            "a.tests.ts",
            "latest/a.ts",
        ] {
            assert!(!is_test_file(path), "{path}");
        }
    }

    #[test]
    fn test_config_names() {
        for path in [
            "jest.config.ts",
            "a/vitest.config.mts",
            "vitest.workspace.ts",
            "playwright.config.ts",
            "cypress.config.js",
            ".mocharc.yml",
            ".mocharc",
            "karma.conf.js",
        ] {
            assert!(is_test_config(path, || false), "{path}");
        }
        assert!(is_test_config("vite.config.ts", || true));
        assert!(!is_test_config("vite.config.ts", || false));
        assert!(!is_test_config("jest.setup.ts", || true));
    }
}
