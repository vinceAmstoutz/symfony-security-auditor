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

use Closure;
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
 * Merges committed (`<ref>...HEAD`), staged and unstaged changes, deduplicated
 * and deterministically ordered. Genuinely untracked files are invisible here.
 *
 * Every invocation is a plumbing form comparing already-hashed objects, or
 * `diff-files` for the working tree. Porcelain `git diff HEAD` is deliberately
 * avoided: it normalizes working-tree files through the `.gitattributes`
 * `filter=<name>` `clean` command, both of which come from the audited
 * repository — as exploitable as the `core.fsmonitor` hook neutralized below.
 * `--relative` aligns paths with `ProjectFile::relativePath()`.
 */
final readonly class ProcessGitChangedFilesResolver implements GitChangedFilesResolverInterface
{
    public const int DEFAULT_TIMEOUT_SECONDS = 60;

    /**
     * @param ?Closure(list<string>, string): Process $gitDiffProcessFactory defaults to a plain `new Process(...)`; tests inject a stub to make a `git diff` call deterministically slow
     */
    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
        private float $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
        private ?Closure $gitDiffProcessFactory = null,
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
        $staged = $this->runGit($projectPath, ['diff-index', '--relative', '--name-only', '--diff-filter=ACMR', '--cached', 'HEAD']);
        $unstaged = $this->runGit($projectPath, ['diff-files', '--relative', '--name-only', '--diff-filter=ACMR']);

        return $this->mergeAndNormalize([...$committed, ...$staged, ...$unstaged]);
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    private function isInsideGitTree(string $projectPath): bool
    {
        $process = new Process(['git', 'rev-parse', '--is-inside-work-tree'], $projectPath);

        try {
            $process->setTimeout($this->timeoutSeconds);
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
            $process->setTimeout($this->timeoutSeconds);
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw GitChangedFilesUnavailableException::forProcessFailure(\sprintf('verify git ref "%s"', $ref), $exception);
        }

        return $process->isSuccessful();
    }

    /**
     * @return Closure(list<string>, string): Process
     */
    private function defaultGitDiffProcessFactory(): Closure
    {
        return $this->buildDefaultGitDiffProcess(...);
    }

    /**
     * `-z` NUL-terminates each path instead of newline-terminating it, and disables
     * git's C-style quoting of non-ASCII bytes AND of literal quotes/backslashes/
     * control characters alike — `core.quotepath=off` alone only covers the former.
     * `core.fsmonitor=` neutralizes the audited (untrusted) repo's own local config:
     * otherwise a hostile `core.fsmonitor` hook set in its `.git/config` runs as an
     * arbitrary command on this working-tree comparison.
     *
     * @param list<string> $argv
     */
    private function buildDefaultGitDiffProcess(array $argv, string $projectPath): Process
    {
        return new Process(['git', '-c', 'core.quotepath=off', '-c', 'core.fsmonitor=', ...$argv, '-z'], $projectPath);
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
        $factory = $this->gitDiffProcessFactory ?? $this->defaultGitDiffProcessFactory();
        $process = $factory($argv, $projectPath);

        try {
            $process->setTimeout($this->timeoutSeconds);
            $process->mustRun();
        } catch (ProcessFailedException $processFailedException) {
            throw GitChangedFilesUnavailableException::fromProcessFailure($argv[\count($argv) - 1] ?? '', $process->getErrorOutput(), $processFailedException);
        } catch (ExceptionInterface $exception) {
            throw GitChangedFilesUnavailableException::forProcessFailure(\sprintf('diff against "%s"', $argv[\count($argv) - 1] ?? ''), $exception);
        }

        return array_values(array_filter(
            explode("\0", $process->getOutput()),
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
