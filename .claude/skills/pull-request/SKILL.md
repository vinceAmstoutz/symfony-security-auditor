---
name: pull-request
description: Open or edit a pull request on this repository so it passes the `Pull request target` check (base branch, a title of 50 characters or fewer, the template's four sections, a Summary of 750 or fewer, ticked boxes only, stacking). Use before creating or updating any pull request.
---

# Pull request

Work through these steps in order. The `Pull request target` check runs the same rules on every edit and fails the pull request on any of them.

## 1. Pick the base

Read [`.github/PULL_REQUEST_TEMPLATE.md`](../../../.github/PULL_REQUEST_TEMPLATE.md) → `## Target branch`. Tick the release branch the change is headed for (`1.x` for bug fixes and new features) and open the pull request against that branch.

## 2. Write the title and the body

Fill in [`.github/PULL_REQUEST_TEMPLATE.md`](../../../.github/PULL_REQUEST_TEMPLATE.md) and keep the top of the PR short:

- **Title: 50 characters or fewer**, same [Conventional Commits](https://www.conventionalcommits.org/) format as a commit subject.
- **Four sections, in this order:** `## Summary`, `## Type of change`, `## Target branch`, `## Checklist`. No other sections: the CHANGELOG entry and the commit body carry the implementation, compatibility and upgrade notes.
- **`## Summary`: 750 characters or fewer.** State the user-visible outcome and stop, then add a `Closes #N` or `Refs #N` line when an issue is involved. The summary is the part everyone reads, so it must stay skimmable.
- **Only the ticked boxes** under Type of change, Target branch and Checklist: delete the others and every template instruction. The Checklist lists only what CI cannot check; its license box is always ticked.
- **Label** the PR `bug` or `enhancement` and assign it to the maintainer.

**Stack as little as possible.** Open every PR against its release branch and stack it on another open PR only when it needs code that PR adds, never because both touch `CHANGELOG.md`, `CLAUDE.md` or the docs, whose conflicts are resolved by updating the branch once the first one merges. When splitting work into several PRs, cut along code dependencies so each builds and passes on the release branch alone. A stacked PR ticks `stacked` and ends its Summary with `Stacked on #N` and the code it needs from it. Once the parent merges, retarget it, untick `stacked`, drop the `Stacked on` line and update the branch: the squash-merge left it carrying commits the base no longer has; its CI ran on top of unmerged code.

On every edit, the `Pull request target` check ([`.github/scripts/check-pull-request.sh`](../../../.github/scripts/check-pull-request.sh)) fails the PR on a title over 50 characters, a missing, extra or misplaced section, a Summary over 750 characters, an unticked box, leftover template text or a missing license box, a base that does not match the ticked branch and a stacked PR that does not name its parent (or still does once unstacked). Run it before opening or editing a PR:

```bash
PR_TITLE='fix(scan): …' PR_BODY="$(cat body.md)" BASE_REF=1.x \
  sh .github/scripts/check-pull-request.sh
```

**Always squash-merge, never rebase-merge.** Every PR becomes exactly one commit on its base branch. Rebase-merging replays each of the PR's commits individually, with a fresh SHA apiece, even when nothing about them changed.

## 3. Check before sending

Write the body to a file in the scratchpad and run the check with the real title and base. Fix every failure before creating or editing the pull request, then label it and assign it as step 2 says.

## 4. After the parent of a stacked pull request merges

Retarget it, untick `stacked`, drop the `Stacked on` line, update the branch and run the check again.
