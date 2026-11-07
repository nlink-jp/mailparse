# CLAUDE.md — mailparse

Organization rules: https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md
Read AGENTS.md first.

## Non-negotiable rules

- **Only the standard library and the two approved Go-team packages** (`golang.org/x/text`,
  `golang.org/x/net/html`). No other `require` line, and never a community package.
- **Never drop silently.** Malformed input, a repair, a guess or a limit becomes a `Warning` with a code.
- **Never panic, never recurse without a bound.** Run `make fuzz` after any change to a reader.
- **Keep order and duplicates.** Do not collapse header fields or address lists.
- **Tests with every change**: a fixture or unit test that fails without the change.
- **make lint before every commit**, not only the tests.
- **Fixtures are fictional**: RFC 2606 domains, RFC 5737 addresses. Real messages never enter the repository.
- **Docs in sync**: README.md and README.ja.md in the same commit.

## Communication Language

All communication between contributors and Claude Code is conducted in **Japanese**.
