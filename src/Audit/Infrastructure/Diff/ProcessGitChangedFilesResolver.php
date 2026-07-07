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

use Override;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\GitChangedFilesUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;

use function Symfony\Component\String\u;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Resolves the set of changed files via two git invocations:
 *
 *   1. `git diff --relative --name-only --diff-filter=ACMR <ref>...HEAD`
 *      — committed changes that diverge from the ref's merge base. The triple
 *      dot semantics handle topic branches diverged from the ref correctly:
 *      only changes ON the branch are returned, not changes the ref accrued
 *      since branch point.
 *
 *   2. `git diff --relative --name-only --diff-filter=ACMR HEAD`
 *      — uncommitted changes against HEAD: staged changes (including files
 *      already `git add`ed) plus unstaged edits to already-tracked files.
 *      `git diff` never reports genuinely untracked files (ones never staged
 *      at all) — those are invisible to this resolver. Merged into the result
 *      so a local dev running `audit:run --since=main` sees their staged and
 *      already-tracked in-flight work too.
 *
 * `--relative` rewrites paths relative to `$projectPath` instead of the git
 * root, and excludes changes outside it — required so the result lines up
 * with `ProjectFile::relativePath()` when the audited project is a
 * subdirectory of a larger repository (a monorepo layout).
 *
 * Both lists are merged, deduplicated, and returned in deterministic order.
 */
final readonly class ProcessGitChangedFilesResolver implements GitChangedFilesResolverInterface
{
    public const int DEFAULT_TIMEOUT_SECONDS = 60;

    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
        private int $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
    ) {}

    /**
     * @throws GitChangedFilesUnavailableException
     */
    #[Override]
    public function changedSince(string $projectPath, string $ref): array
    {
        if (!$this->filesystem->exists(\sprintf('%s/.git', $projectPath)) && !$this->isInsideGitTree($projectPath)) {
            throw GitChangedFilesUnavailableException::forNonGitDirectory($projectPath);
        }

        if (!$this->refExists($projectPath, $ref)) {
            throw GitChangedFilesUnavailableException::forUnknownRef($ref, $projectPath);
        }

        $committed = $this->runGit($projectPath, ['diff', '--relative', '--name-only', '--diff-filter=ACMR', \sprintf('%s...HEAD', $ref)]);
        $uncommitted = $this->runGit($projectPath, ['diff', '--relative', '--name-only', '--diff-filter=ACMR', 'HEAD']);

        return $this->mergeAndNormalize([...$committed, ...$uncommitted]);
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    private function isInsideGitTree(string $projectPath): bool
    {
        $process = new Process(['git', 'rev-parse', '--is-inside-work-tree'], $projectPath);

        try {
            $process->setTimeout((float) $this->timeoutSeconds);
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw GitChangedFilesUnavailableException::forProcessFailure(\sprintf('determine whether "%s" is a git working tree', $projectPath), $exception);
        }

        return $process->isSuccessful() && 'true' === u($process->getOutput())->trim()->toString();
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    private function refExists(string $projectPath, string $ref): bool
    {
        $process = new Process(['git', 'rev-parse', '--verify', '--quiet', $ref], $projectPath);

        try {
            $process->setTimeout((float) $this->timeoutSeconds);
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw GitChangedFilesUnavailableException::forProcessFailure(\sprintf('verify git ref "%s"', $ref), $exception);
        }

        return $process->isSuccessful();
    }

    /**
     * @param list<string> $argv
     *
     * @return list<string>
     *
     * @throws GitChangedFilesUnavailableException
     */
    private function runGit(string $projectPath, array $argv): array
    {
        // core.quotepath=off stops git C-quoting non-ASCII paths, which would never match ProjectFile paths.
        $process = new Process(['git', '-c', 'core.quotepath=off', ...$argv], $projectPath);

        try {
            $process->mustRun();
        } catch (ProcessFailedException $processFailedException) {
            throw GitChangedFilesUnavailableException::fromProcessFailure($argv[\count($argv) - 1] ?? '', $process->getErrorOutput(), $processFailedException);
        }

        $split = preg_split('/\R/', u($process->getOutput())->trim()->toString());
        $lines = false !== $split ? $split : [];

        return array_values(array_filter(
            $lines,
            static fn (string $line): bool => !u($line)->trim()->isEmpty(),
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
            $trimmed = u($path)->trim()->trimPrefix('./')->toString();
            if ('' !== $trimmed) {
                $normalized[] = $trimmed;
            }
        }

        $result = array_unique($normalized);
        sort($result);

        return $result;
    }
}
