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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Diff;

use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\GitChangedFilesUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Resolves the set of changed files via two git invocations:
 *
 *   1. `git diff --name-only --diff-filter=ACMR <ref>...HEAD`
 *      — committed changes that diverge from the ref's merge base. The triple
 *      dot semantics handle topic branches diverged from the ref correctly:
 *      only changes ON the branch are returned, not changes the ref accrued
 *      since branch point.
 *
 *   2. `git diff --name-only --diff-filter=ACMR HEAD`
 *      — uncommitted changes against HEAD (staged + unstaged + untracked
 *      tracked-paths). Merged into the result so a local dev running
 *      `audit:run --since=main` sees their in-flight work too.
 *
 * Both lists are merged, deduplicated, and returned in deterministic order.
 */
final readonly class ProcessGitChangedFilesResolver implements GitChangedFilesResolverInterface
{
    public function changedSince(string $projectPath, string $ref): array
    {
        if (!is_dir($projectPath.'/.git') && !$this->isInsideGitTree($projectPath)) {
            throw GitChangedFilesUnavailableException::forNonGitDirectory($projectPath);
        }

        if (!$this->refExists($projectPath, $ref)) {
            throw GitChangedFilesUnavailableException::forUnknownRef($ref, $projectPath);
        }

        $committed = $this->runGit($projectPath, ['diff', '--name-only', '--diff-filter=ACMR', $ref.'...HEAD']);
        $uncommitted = $this->runGit($projectPath, ['diff', '--name-only', '--diff-filter=ACMR', 'HEAD']);

        return $this->mergeAndNormalize([...$committed, ...$uncommitted]);
    }

    private function isInsideGitTree(string $projectPath): bool
    {
        $process = new Process(['git', 'rev-parse', '--is-inside-work-tree'], $projectPath);
        $process->run();

        return $process->isSuccessful() && 'true' === trim($process->getOutput());
    }

    private function refExists(string $projectPath, string $ref): bool
    {
        $process = new Process(['git', 'rev-parse', '--verify', '--quiet', $ref], $projectPath);
        $process->run();

        return $process->isSuccessful();
    }

    /**
     * @param list<string> $argv
     *
     * @return list<string>
     */
    private function runGit(string $projectPath, array $argv): array
    {
        $process = new Process(['git', ...$argv], $projectPath);

        try {
            $process->mustRun();
        } catch (ProcessFailedException $processFailedException) {
            throw GitChangedFilesUnavailableException::fromProcessFailure($argv[\count($argv) - 1] ?? '', $process->getErrorOutput(), $processFailedException);
        }

        $lines = preg_split('/\R/', trim($process->getOutput())) ?: [];

        return array_values(array_filter(
            $lines,
            static fn (string $line): bool => '' !== trim($line),
        ));
    }

    /**
     * @param list<string> $paths
     *
     * @return list<string>
     */
    private function mergeAndNormalize(array $paths): array
    {
        $normalized = [];
        foreach ($paths as $path) {
            $trimmed = ltrim(trim($path), './');
            if ('' !== $trimmed) {
                $normalized[$trimmed] = true;
            }
        }

        $result = array_keys($normalized);
        sort($result);

        return $result;
    }
}
