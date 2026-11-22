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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Utf8Normalizer;

use function Symfony\Component\String\u;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 *
 * Returns, sorted and deduplicated, the files committed on the branch since
 * its merge base with the ref and the staged, unstaged and untracked files
 * no `.gitignore` excludes, relative to the project path and only under it.
 * A type change counts: a symlink replaced by a regular file holds code the
 * scan never read. Never runs a `.gitattributes` content filter of the
 * audited repository.
 */
final readonly class ProcessGitChangedFilesResolver implements GitChangedFilesResolverInterface
{
    public const int DEFAULT_TIMEOUT_SECONDS = 60;

    private const int UNKNOWN_REF_EXIT_CODE = 1;

    private const string NOT_A_REPOSITORY = 'not a git repository';

    /**
     * @param ?Closure(list<string>, string): Process $gitDiffProcessFactory defaults to the hardened git process
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

        $committed = $this->runGit($projectPath, ['diff', '--relative', '--name-only', '--diff-filter=ACMRT', \sprintf('%s...HEAD', $ref)]);
        $staged = $this->runGit($projectPath, ['diff-index', '--relative', '--name-only', '--diff-filter=ACMRT', '--cached', 'HEAD']);
        $unstaged = $this->runGit($projectPath, ['diff-files', '--relative', '--name-only', '--diff-filter=ACMRT']);
        $untracked = $this->runGit($projectPath, ['ls-files', '--others', '--exclude-standard']);

        return $this->mergeAndNormalize([...$committed, ...$staged, ...$unstaged, ...$untracked]);
    }

    /**
     * @throws GitChangedFilesUnavailableException
     */
    private function isInsideGitTree(string $projectPath): bool
    {
        $process = $this->revParse($projectPath, ['--is-inside-work-tree'], \sprintf('determine whether "%s" is a git working tree', $projectPath));

        return $this->gitAnswered($process, $projectPath) && 'true' === u($process->getOutput())->trim()->toString();
    }

    /**
     * Returns false for a ref that names no object.
     *
     * @throws GitChangedFilesUnavailableException
     */
    private function refExists(string $projectPath, string $ref): bool
    {
        $process = $this->revParse($projectPath, ['--verify', '--quiet', $ref], \sprintf('verify git ref "%s"', $ref));

        return self::UNKNOWN_REF_EXIT_CODE !== $process->getExitCode() && $this->gitAnswered($process, $projectPath);
    }

    /**
     * Returns false when git finds no repository; throws with git's own
     * message on any other failure.
     *
     * @throws GitChangedFilesUnavailableException
     */
    private function gitAnswered(Process $process, string $projectPath): bool
    {
        if ($process->isSuccessful()) {
            return true;
        }

        if (str_contains($process->getErrorOutput(), self::NOT_A_REPOSITORY)) {
            return false;
        }

        throw GitChangedFilesUnavailableException::forRefusedRepository($projectPath, $process->getErrorOutput());
    }

    /**
     * @param list<string> $argv
     *
     * @throws GitChangedFilesUnavailableException
     */
    private function revParse(string $projectPath, array $argv, string $operation): Process
    {
        $process = new Process(['git', 'rev-parse', ...$argv], $projectPath);

        try {
            $process->setTimeout($this->timeoutSeconds);
            $process->run();
        } catch (ExceptionInterface $exception) {
            throw GitChangedFilesUnavailableException::forProcessFailure($operation, $exception);
        }

        return $process;
    }

    /**
     * @return Closure(list<string>, string): Process
     */
    private function defaultGitDiffProcessFactory(): Closure
    {
        return $this->buildDefaultGitDiffProcess(...);
    }

    /**
     * Overrides the audited repository's config so neither its `core.fsmonitor`
     * hook nor its `clean` filter runs: the stat check it may relax would let
     * an archived index entry match and be re-hashed through that filter.
     * `-z` turns off git's quoting of paths; `--` keeps a file named `HEAD`
     * from being read as a revision.
     *
     * @param list<string> $argv
     */
    private function buildDefaultGitDiffProcess(array $argv, string $projectPath): Process
    {
        return new Process(['git', '-c', 'core.quotepath=off', '-c', 'core.fsmonitor=', '-c', 'core.checkStat=default', '-c', 'core.trustctime=true', ...$argv, '-z', '--'], $projectPath);
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
            explode("\0", Utf8Normalizer::normalize($process->getOutput())),
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
