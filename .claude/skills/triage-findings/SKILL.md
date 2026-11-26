---
name: triage-findings
description: Process an external code review, security audit or AI review scan of this codebase (an "audit round", a list of findings, reviewer comments): reproduce each medium-or-higher finding as a failing PHPUnit test, fix only the ones that turn red, reject the rest with a reason. Use before patching anything a report claims.
---

# Triage review findings

## The acceptance test

AI review scans over-report: they inflate severity and raise plausible-but-wrong findings. Do **not** patch a finding on the strength of its description. The acceptance test for any reported medium+ finding is a single question:

> Can it be expressed as a failing PHPUnit test, red for the right reason on the current code?

- **Yes → it is real.** That failing test _is_ the regression test; commit it with the fix (red → green). Which suite layer had to grow to express it tells you where the hole was: usually "no E2E ran this config combination."
- **No → reject it.** A finding no one can turn red is noise; record why and move on. Never add production code, a guard, or a defensive branch for a scenario you cannot make a test reach: that is untested code by definition and it dilutes the signal of the next scan.

This keeps the finding backlog honest and steadily converts each genuine discovery into a permanent guard, rather than repeatedly re-running the same broad scan to rediscover the same gaps.

## Procedure

1. List every finding in a scratchpad file: id, claimed severity, file and line, the claim in one sentence.
2. Take one finding at a time, most severe first. Read the code it names, then write **one** test at the lowest suite layer that can express it: `Unit`, `Integration`, `EndToEnd`, or `ContainerBackedAuditEndToEndTest` when the claim depends on the compiled container or a config combination.
3. Run it. **Red for the reason the finding gives** → the finding is real: make it green with the minimum change, refactor while green, then move to the next one. **Green, or red for another reason** → reject it: write down why, delete the test, change no production code.
4. Each real finding gets one `Bugfixes 🐛` line in `CHANGELOG.md` (the `changelog.md` rule loads when you open it); a finding that has a published CVE or GHSA id goes under `Security 🔒`. Ask the maintainer when in doubt.
5. Finish with a table: finding, verdict (`fixed` / `rejected`), the test that proves it or the reason it was rejected. Earlier rounds landed as one pull request per round (`fix: round-8 audit findings before 1.22.0`).
