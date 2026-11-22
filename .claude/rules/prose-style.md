# Prose Style Rule

Two habits of AI-written text are banned from everything written in this repository: Markdown files, code comments and docblocks, CHANGELOG entries, commit messages, pull request descriptions and the text the tool prints.

## Banned

| Pattern | Example | Write instead |
| --- | --- | --- |
| The em dash `—`, or an en dash or a spaced hyphen standing in for one | `` `audit:diff` compares two reports — in the bundle and the binary alike. `` | A period, a colon, a comma or parentheses: `` `audit:diff` compares two reports. It runs in the bundle and in the binary. `` |
| A comma before `and`, in a list or between two clauses | `It scans, filters, and reports.` `The run stops, and the report says so.` | `It scans, filters and reports.` `The run stops and the report says so.` Split a long sentence in two rather than chaining clauses. |

A hyphen stays fine where it is not punctuation: compound words (`cost-aware`), options (`--dry-run`), numeric ranges (`4-8`) and list markers.

## Exceptions

- Code, code blocks and command lines.
- Output the program really prints, quoted in the docs: quote it exactly and fix the docs when the code that prints it changes.
- Text quoted from a third party, such as a provider's error message or a license.
- The released sections of `CHANGELOG.md` (already published as release notes) and its release headings (whose format the release scripts read).

## Enforcement

CI fails a pull request whose Markdown, PHP comments or PHP docblocks break this rule: the Lint job runs `.github/scripts/check-prose.sh` on every tracked `.md` and `.php` file. It skips code blocks, inline code, PHP code and strings, the released sections of `CHANGELOG.md`, fixture directories (`Fixture/`, `Fixtures/`) and the PHP of `examples/`, whose text is test data. Run it before pushing, or `bin/castor lint:docs`:

```bash
sh .github/scripts/check-prose.sh
```

Commit messages, pull request text and printed strings follow the rule too, but no check enforces it there yet. Rewrite such a sentence when you edit it. Changing a string the tool prints is a behavior change: give it a CHANGELOG entry and accept the difference in the compatibility checks.
