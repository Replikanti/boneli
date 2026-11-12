# Architecture Decision Records

[`../ARCHITECTURE.md`](../ARCHITECTURE.md) is the baseline design.
Decisions made since get one file each here:

- **File**: `NNN-kebab-slug.md`, where `NNN` is the next free number, starting
  at 001. Numbers are never reused; rejected ADRs keep their file.
- **Title line**: `# ADR-NNN: <title>`.
- **Header**: `- Status: proposed | accepted | rejected | superseded by ADR-MMM`
  and `- Date: YYYY-MM-DD`.
- **Sections**: `Context`, `Decision`, `Consequences` (including the negative
  ones), `Alternatives considered`. A proposed ADR adds `Accept when`: the
  event or measurement that settles it.
- **Lifecycle**: a proposed ADR may be edited freely. An accepted ADR changes
  only its status line; changing the decision means a new ADR that
  supersedes it. A decision that changes the baseline design updates
  `ARCHITECTURE.md` in the same PR and names the ADR there.
- **When**: a PR that makes a design decision adds or flips an ADR, and issues
  labelled `needs-adr` name the ADR they will produce.
- **Public repository**: ADRs here cover the runner and the code in this
  repository. Decisions about pricing, strategy, playbooks or benchmark cases
  belong to the private repository.

Index: `ls docs/adr/`. Status index: `grep -H '^- Status' docs/adr/[0-9]*.md`.
