# Pull Requests

Rules for opening and merging a pull request; `CLAUDE.md` carries the short version.

Fill in [`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md) and keep the top of the PR short:

- **Title: 50 characters or fewer**, same [Conventional Commits](https://www.conventionalcommits.org/) format as a commit subject.
- **Four sections, in this order:** `## Summary`, `## Type of change`, `## Target branch`, `## Checklist`. No other sections: the CHANGELOG entry and the commit body carry the implementation, compatibility and upgrade notes.
- **`## Summary`: 500 characters or fewer.** State the user-visible outcome and stop, then add a `Closes #N` or `Refs #N` line when an issue is involved — the summary is the part everyone reads, so it must stay skimmable.
- **Only the ticked boxes** under Type of change, Target branch and Checklist: delete the others and every template instruction. The Checklist lists only what CI cannot check, and its license box is always ticked.
- **Label** the PR `bug` or `enhancement` and assign it to the maintainer.

**Stack as little as possible.** Open every PR against its release branch, and stack it on another open PR only when it needs code that PR adds — never because both touch `CHANGELOG.md`, `CLAUDE.md` or the docs, whose conflicts are resolved by updating the branch once the first one merges. When splitting work into several PRs, cut along code dependencies so each builds and passes on the release branch alone. A stacked PR ticks `stacked` and ends its Summary with `Stacked on #N` and the code it needs from it. Once the parent merges, retarget it, untick `stacked`, drop the `Stacked on` line and update the branch — the squash-merge left it carrying commits the base no longer has, and its CI ran on top of unmerged code.

On every edit, the `Pull request target` check ([`.github/scripts/check-pull-request.sh`](../.github/scripts/check-pull-request.sh)) fails the PR on a title over 50 characters, a missing, extra or misplaced section, a Summary over 500 characters, an unticked box, leftover template text or a missing license box, a base that does not match the ticked branch, and a stacked PR that does not name its parent — or still does once unstacked. Run it before opening or editing a PR:

```bash
PR_TITLE='fix(scan): …' PR_BODY="$(cat body.md)" BASE_REF=1.x \
  sh .github/scripts/check-pull-request.sh
```

**Always squash-merge, never rebase-merge.** Every PR becomes exactly one commit on its base branch. Rebase-merging replays each of the PR's commits individually — with a fresh SHA apiece, even when nothing about them changed.

**Exception: the `chore: release X.Y.Z` PR that merges `<N>.x` into `main`.** Use a regular merge (a merge commit) there instead, never squash and never rebase. `main` is supposed to end up with the exact same commit SHAs as `<N>.x` — that's how every release before this one actually happened (PR #226, for 1.18.0). Squashing collapses `<N>.x`'s commits into one new SHA that doesn't exist on `<N>.x`, so the two branches permanently diverge in commit identity and need a cherry-pick-back reconciliation after every single release. Rebase-merging is worse: it replays every commit `<N>.x` has accumulated since it last diverged from `main` with a fresh SHA apiece — which is how PR #305 quietly turned a one-commit release into ~40 replayed commits landing on `main` and broke `Commit Lint` (see [Branches & maintenance](versioning.md#branches--maintenance)).
