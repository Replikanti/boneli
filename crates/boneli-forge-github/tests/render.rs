//! The title, the body, the comment and the commit message (ADR-014, D8).

mod support;

use boneli_domain::{
    Budget, BudgetDimension, CheckStatus, Citation, CommitSha, EvidenceRef, Overrun, RunId,
    TestStatus, TicketSource, Usage,
};
use boneli_forge_github::render::{
    self, MAX_BODY, MAX_FIXED, MAX_QUESTIONS, MAX_TITLE, check_status_label, commit_message,
    escape, permalink, pull_request_body, questions_comment, seconds, test_status_label, title,
    usd, water_fill,
};
use support::*;

/// The lines of `markdown` that CommonMark reads as indented code: four
/// spaces, after a blank line or another code line (an indented line
/// after a paragraph line continues the paragraph). Returns, per line,
/// whether it is code.
fn code_lines(markdown: &str) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    let mut previous_blank = true;
    let mut in_code = false;
    for line in markdown.split('\n') {
        let blank = line.trim().is_empty();
        let code = line.starts_with("    ") && !blank && (previous_blank || in_code);
        if code {
            in_code = true;
        } else if !blank {
            in_code = false;
        }
        out.push((code, line));
        previous_blank = blank;
    }
    out
}

/// Text that must never be live outside a code block.
const HOSTILE: [&str; 14] = [
    "```",
    "~~~",
    "</pre>",
    "<img src=x onerror=alert(1)>",
    "@user",
    "@org/team",
    "#1",
    "Closes #1",
    "owner/repo#1",
    "<!--",
    "[x](javascript:alert(1))",
    "- [ ] task",
    "> quote",
    "| a | b |",
];

fn hostile_text() -> String {
    let mut text = String::new();
    for token in HOSTILE {
        text.push_str(token);
        text.push('\n');
        text.push_str(&format!("prefix {token} suffix\n"));
    }
    text.push_str("lone\rcarriage return\r\nCRLF\u{2028}ls\u{2029}ps\u{202e}rlo\u{200b}zwsp\u{0}nul\u{1b}[31mesc\n");
    text.push_str("\n\n    indented\n\ttab\n");
    text
}

/// Every hostile token appears only on code lines, no list or block quote
/// is opened outside code, and no raw control or invisible character is
/// left anywhere.
fn assert_inert(markdown: &str) {
    for (code, line) in code_lines(markdown) {
        if code || line.trim().is_empty() {
            continue;
        }
        for token in HOSTILE {
            assert!(!line.contains(token), "{token:?} outside code: {line:?}");
        }
        for marker in ["- ", "* ", "+ ", "> ", "1. ", "<"] {
            assert!(!line.starts_with(marker), "{line:?}");
        }
        assert!(!line.starts_with(' '), "{line:?}");
        assert!(!line.contains('@'), "{line:?}");
    }
    for c in markdown.chars() {
        assert!(
            c == '\n'
                || c == '\t'
                || !(c.is_control()
                    || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202e}' | '\u{200b}')),
            "raw {c:?} in the output"
        );
    }
}

fn hostile_request() -> boneli_app::PullRequest {
    let mut request = request();
    request.analysis.content = hostile_text().into_bytes();
    request.test.content = hostile_text().into_bytes();
    let base = request.base.clone();
    request.citations.push(Citation {
        path: "src/a b#c?.rs".to_owned(),
        line: 9,
        sha: base,
        quote: hostile_text(),
    });
    request.ticket.title = "Closes #1 @user\n<b>x</b>".to_owned();
    request
}

#[test]
fn hostile_text_stays_in_code_blocks() {
    let body = pull_request_body(&hostile_request(), &repository());
    assert!(body.cut.is_empty());
    assert_inert(&body.text);
    // The hostile text is there, as code.
    let code: Vec<&str> = code_lines(&body.text)
        .into_iter()
        .filter(|(c, _)| *c)
        .map(|(_, l)| l)
        .collect();
    for token in HOSTILE {
        assert!(code.iter().any(|l| l.contains(token)), "{token}");
    }
    let comment = questions_comment(&[hostile_text(), "@user Closes #1".to_owned()]);
    assert_inert(&comment.text);
    // Empty agent text: a generated line, not an empty code block.
    let mut empty = request();
    empty.analysis.content.clear();
    empty.test.content.clear();
    let text = pull_request_body(&empty, &repository()).text;
    assert_eq!(text.matches("_(empty)_").count(), 2, "{text}");
    assert_inert(&questions_comment(&[String::new()]).text);
    // A cut block stays inert too.
    let mut huge = hostile_request();
    huge.analysis.content = hostile_text().repeat(2_000).into_bytes();
    let cut = pull_request_body(&huge, &repository());
    assert_eq!(cut.cut, [1]);
    assert_inert(&cut.text);
}

#[test]
fn escape_rule() {
    for (input, expected) in [
        ("a\rb", "a\\u{000D}b"),
        ("a\r\nb", "a\\u{000D}\nb"),
        ("\u{0}", "\\u{0000}"),
        ("\u{1b}[31m", "\\u{001B}[31m"),
        ("\u{7f}", "\\u{007F}"),
        ("\u{85}", "\\u{0085}"),
        ("\u{2028}\u{2029}", "\\u{2028}\\u{2029}"),
        ("\u{202e}x", "\\u{202E}x"),
        ("\u{200b}", "\\u{200B}"),
        ("\u{feff}", "\\u{FEFF}"),
        ("\u{ad}", "\\u{00AD}"),
        ("\u{e0041}", "\\u{E0041}"),
        ("\u{2024}", "\u{2024}"),
        ("a\tb\nc", "a\tb\nc"),
        ("\u{17e}\u{3164}", "\u{17e}\\u{3164}"),
        ("```@x #1", "```@x #1"),
    ] {
        assert_eq!(escape(input), expected, "{input:?}");
    }
    // The title escapes LF and TAB too.
    assert_eq!(title("a\nb\tc\rd"), "Fix: a\\u{000A}b\\u{0009}c\\u{000D}d");
}

#[test]
fn non_utf8_is_shown_lossily_with_note() {
    let mut request = request();
    request.analysis.content = b"bad \xff byte".to_vec();
    let text = pull_request_body(&request, &repository()).text;
    assert!(text.contains("_The analysis is not valid UTF-8;"), "{text}");
    assert!(text.contains("    bad \u{fffd} byte\n"), "{text}");
    assert!(!text.contains("_The test is not valid UTF-8;"));
}

#[test]
fn body_cap_arithmetic() {
    assert_eq!(
        water_fill(60_000, &[2_000, 50_000, 30_000]),
        [2_000, 29_000, 29_000]
    );
    assert_eq!(
        water_fill(60_000, &[20_000, 20_000, 20_001]),
        [20_000, 20_000, 20_000]
    );
    assert_eq!(water_fill(60_000, &[0, 0, 0]), [0, 0, 0]);
    assert_eq!(water_fill(10, &[100, 100, 100]), [3, 3, 4]);
    assert_eq!(water_fill(0, &[1]), [0]);
    let cap = 1_000;
    for need in [0, 1, cap - 1, cap, cap + 1] {
        let shares = water_fill(cap, &[need]);
        assert_eq!(shares, [need.min(cap)], "{need}");
    }
    assert_eq!(
        water_fill(3 * cap, &[cap - 1, cap, cap + 1]),
        [cap - 1, cap, cap + 1]
    );
    assert_eq!(
        water_fill(3 * cap - 1, &[cap - 1, cap, cap + 1]),
        [cap - 1, cap, cap]
    );
    assert!(water_fill(5, &[]).is_empty());

    // The whole body: exactly 65,536 bytes when the needs fit exactly, and
    // one byte more cuts exactly one block.
    let body_for = |k: usize| {
        let mut request = request();
        request.analysis.content = vec![b'a'; k];
        pull_request_body(&request, &repository())
    };
    let one = body_for(1).text.len();
    let k = MAX_BODY - one + 1;
    let exact = body_for(k);
    assert_eq!(exact.text.len(), MAX_BODY);
    assert!(exact.cut.is_empty());
    let over = body_for(k + 1);
    assert_eq!(over.cut, [1]);
    assert!(over.text.len() <= MAX_BODY);
    assert!(
        over.text
            .contains("the full text is the run's evidence `sha256-analysis`")
    );
}

#[test]
fn title_cap_arithmetic() {
    let t = title(&"a".repeat(251));
    assert_eq!(t.len(), 256);
    assert!(!t.ends_with('…'));
    let t = title(&"a".repeat(252));
    assert_eq!(t, format!("Fix: {}…", "a".repeat(248)));
    assert_eq!(t.len(), MAX_TITLE);
    let t = title(&"\u{20ac}".repeat(85));
    assert_eq!(t.len(), 254);
    assert_eq!(t, format!("Fix: {}…", "\u{20ac}".repeat(82)));
    // Escapes count after they are expanded.
    let t = title(&"\n".repeat(100));
    assert!(t.len() <= MAX_TITLE && t.ends_with('…'));
}

#[test]
fn fixed_parts_bound() {
    let mut request = request();
    let id = "r".repeat(128);
    request.run = RunId::new(id.clone());
    request.ticket.source = TicketSource::Jira;
    request.ticket.key = "K".repeat(64);
    for attached in [&mut request.diff, &mut request.test, &mut request.analysis] {
        attached.reference = EvidenceRef::parse(&"e".repeat(128)).expect("ref");
        attached.content = b"\xff".to_vec();
    }
    request.spent = Usage {
        cost_micro_usd: u64::MAX,
        duration_ms: u64::MAX,
    };
    request.overrun = Some(Overrun {
        dimension: BudgetDimension::Duration,
        spent: request.spent,
        budget: Budget {
            cost_micro_usd: u64::MAX,
            duration_ms: u64::MAX,
        },
    });
    let body = pull_request_body(&request, &repository());
    assert!(body.fixed <= MAX_FIXED, "{}", body.fixed);
    assert!(body.text.contains(&format!("Run `{id}`")));
    let comment = questions_comment(&vec!["q".to_owned(); 10_000]);
    assert!(comment.fixed <= MAX_FIXED, "{}", comment.fixed);
    assert_eq!(comment.text.matches("### Question").count(), MAX_QUESTIONS);
    assert!(comment.text.contains("_9936 more questions are not shown"));
    // Ids outside the safe form are left out, never shown.
    request.run = RunId::new("r`un @x".to_owned());
    request.ticket.key = "K-1 @x".to_owned();
    let text = pull_request_body(&request, &repository()).text;
    assert!(!text.contains("@x"), "{text}");
    assert!(text.contains("Ticket: Jira (its key is not shown)"));
}

#[test]
fn fixes_line_only_for_github_ticket() {
    let body = |source, key: &str| {
        let mut request = request();
        request.ticket.source = source;
        request.ticket.key = key.to_owned();
        pull_request_body(&request, &repository()).text
    };
    assert!(body(TicketSource::GitHub, "7").starts_with("Fixes #7\n\n"));
    for (source, key, line) in [
        (TicketSource::Jira, "PROJ-12", "Ticket: Jira `PROJ-12`"),
        (TicketSource::GitLab, "7", "Ticket: GitLab `7`"),
        (
            TicketSource::Sentry,
            "abc.def_1",
            "Ticket: Sentry `abc.def_1`",
        ),
        (
            TicketSource::GitHub,
            "0123",
            "Ticket: GitHub (its key is not shown)",
        ),
        (
            TicketSource::GitHub,
            "owner/repo#1",
            "Ticket: GitHub (its key is not shown)",
        ),
    ] {
        let text = body(source, key);
        assert!(text.starts_with(&format!("{line}\n\n")), "{text}");
        assert!(!text.contains("Fixes"), "{text}");
    }
    // The commit message never closes anything.
    let mut ticket = ticket("7");
    let run = RunId::new("run-1".to_owned());
    assert_eq!(
        commit_message(&ticket, &run),
        "boneli: fix for GitHub ticket 7\n\nRun run-1\n"
    );
    ticket.source = TicketSource::Jira;
    ticket.key = "Closes #1".to_owned();
    assert_eq!(
        commit_message(&ticket, &RunId::new("../x".to_owned())),
        "boneli: fix for a Jira ticket\n"
    );
}

#[test]
fn citation_permalinks() {
    let repo = repository();
    let base = BASE;
    for (path, encoded) in [
        ("src/a b#c?.rs", "src/a%20b%23c%3F.rs"),
        ("src/\u{17e}.rs", "src/%C5%BE.rs"),
        ("a/(x)[y]<z>.rs", "a/%28x%29%5By%5D%3Cz%3E.rs"),
        ("a-b_c.d~e/f", "a-b_c.d~e/f"),
        ("%41", "%2541"),
    ] {
        let link = permalink(&repo, base, path, 12);
        assert_eq!(
            link,
            format!("https://github.com/octo-org/demo.repo/blob/{base}/{encoded}#L12")
        );
        // Decoding gives the path back.
        let mut bytes = Vec::new();
        let raw = encoded.as_bytes();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%' {
                let hex = std::str::from_utf8(&raw[i + 1..i + 3]).expect("hex");
                bytes.push(u8::from_str_radix(hex, 16).expect("hex"));
                i += 3;
            } else {
                bytes.push(raw[i]);
                i += 1;
            }
        }
        assert_eq!(bytes, path.as_bytes());
    }
    let text = pull_request_body(&request(), &repo).text;
    assert!(text.contains(&format!(
        "[Citation 1 of 2](https://github.com/octo-org/demo.repo/blob/{BASE}/src/parse.rs#L12)\n\n    src/parse.rs:12\n    let first = input[0];\n"
    )), "{text}");
    // A path too long for a link still shows, as code.
    let mut long = request();
    long.citations[0].path = format!("src/{}", " ".repeat(400));
    let text = pull_request_body(&long, &repo).text;
    assert!(text.contains("Citation 1 of 2 (its path is too long for a link)"));
    let _ = CommitSha::parse(BASE).expect("sha");
}

#[test]
fn every_status_has_a_distinct_label() {
    let tests = [
        TestStatus::Passed,
        TestStatus::FailedOnAssertion,
        TestStatus::FailedToBuild,
        TestStatus::Errored,
        TestStatus::TimedOut,
        TestStatus::Unknown,
    ];
    let checks = [
        CheckStatus::Passed,
        CheckStatus::Failed,
        CheckStatus::NotConfigured,
        CheckStatus::Unknown,
    ];
    let mut labels: Vec<&str> = tests.iter().map(|s| test_status_label(*s)).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), tests.len());
    let mut labels: Vec<&str> = checks.iter().map(|s| check_status_label(*s)).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), checks.len());
    let mut request = request();
    request.checks.reproduction_test = TestStatus::TimedOut;
    request.checks.lint = CheckStatus::Failed;
    let text = pull_request_body(&request, &repository()).text;
    assert!(text.contains("| Reproduction test | fails on an assertion | times out |"));
    assert!(text.contains("| Lint | not run | failed |"));
}

#[test]
fn cost_and_overrun_render_exactly() {
    for (micro, shown) in [
        (0, "$0.000000"),
        (1, "$0.000001"),
        (1_234_567, "$1.234567"),
        (u64::MAX, "$18446744073709.551615"),
    ] {
        assert_eq!(usd(micro), shown);
    }
    assert_eq!(seconds(3_723_456), "3723.456 s");
    assert_eq!(seconds(0), "0.000 s");
    assert_eq!(seconds(1), "0.001 s");
    let mut request = request();
    let text = pull_request_body(&request, &repository()).text;
    assert!(text.contains("The run cost $1.234567 and took 3723.456 s of job time."));
    assert!(!text.contains("Over budget"));
    request.overrun = Some(Overrun {
        dimension: BudgetDimension::Cost,
        spent: Usage {
            cost_micro_usd: 1_500_000,
            duration_ms: 10,
        },
        budget: Budget {
            cost_micro_usd: 1_000_000,
            duration_ms: 60_000,
        },
    });
    let text = pull_request_body(&request, &repository()).text;
    assert!(text.contains(
        "**Over budget.** The verify job took the run past its cost limit: it used $1.500000 against a limit of $1.000000."
    ), "{text}");
    request.overrun = Some(Overrun {
        dimension: BudgetDimension::Duration,
        spent: Usage {
            cost_micro_usd: 1,
            duration_ms: 61_001,
        },
        budget: Budget {
            cost_micro_usd: 10,
            duration_ms: 60_000,
        },
    });
    let text = pull_request_body(&request, &repository()).text;
    assert!(
        text.contains("past its job time limit: it used 61.001 s against a limit of 60.000 s."),
        "{text}"
    );
}

#[test]
fn saturated_overrun_says_at_least() {
    let mut request = request();
    request.spent = Usage {
        cost_micro_usd: u64::MAX,
        duration_ms: 5,
    };
    request.overrun = Some(Overrun {
        dimension: BudgetDimension::Cost,
        spent: request.spent,
        budget: Budget {
            cost_micro_usd: u64::MAX,
            duration_ms: 10,
        },
    });
    let text = pull_request_body(&request, &repository()).text;
    assert!(text.contains("The run cost at least $18446744073709.551615 and took 0.005 s"));
    assert!(
        text.contains(
            "it used at least $18446744073709.551615 against a limit of $18446744073709.551615."
        ),
        "{text}"
    );
}

#[test]
fn questions_comment_caps_at_65536_bytes() {
    let one = questions_comment(&["x".repeat(100_000)]);
    assert!(one.text.len() <= MAX_BODY);
    assert_eq!(one.cut, [0]);
    assert!(
        one.text
            .ends_with("_Cut here to fit GitHub's limit of 65,536 bytes._\n\n")
    );
    let many = questions_comment(&vec!["y".repeat(5_000); 20]);
    assert!(many.text.len() <= MAX_BODY);
    assert_eq!(many.cut.len(), 20);
    let small = questions_comment(&["short".to_owned(), "z".repeat(100_000)]);
    assert_eq!(small.cut, [1]);
    assert!(small.text.contains("\n    short\n"));
    assert!(small.text.len() <= MAX_BODY);
    // A comment with CRLF text has no raw CR.
    assert!(
        !questions_comment(&["a\r\nb".to_owned()])
            .text
            .contains('\r')
    );
    let _ = render::MAX_LINK;
}
