<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\GitChangedFilesUnavailableException;

/**
 * Resolves the set of project-relative file paths that have changed (added,
 * modified, renamed) between the given git ref and the current working tree.
 *
 * Used by diff-mode audits where CI integrations want to scan only the files
 * touched by a pull request instead of the whole project tree. Implementations
 * must include uncommitted changes (so a local dev `audit:run --since=main`
 * sees their in-flight edits).
 *
 * @throws GitChangedFilesUnavailableException when the project path is not a
 *                                             git working tree, the ref does
 *                                             not resolve, or the git binary
 *                                             is unavailable
 */
interface GitChangedFilesResolverInterface
{
    /**
     * @return list<string> project-relative paths, slash-separated, normalised to no leading `./`
     */
    public function changedSince(string $projectPath, string $ref): array;
}
