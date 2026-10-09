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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem;

use Closure;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Process;

/**
 * The files git tracks although a `.gitignore` pattern matches them: a rule
 * keeps only untracked files out of a repository.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GitTrackedIgnoredFiles
{
    /**
     * @param ?Closure(string): Process $processFactory defaults to the `git ls-files` listing run in the project; tests inject a stub to make git unavailable or slow
     */
    public function __construct(
        private LoggerInterface $logger,
        private ?Closure $processFactory = null,
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @return list<string> paths relative to the project, in git's own spelling
     */
    public function in(string $projectPath): array
    {
        $process = ($this->processFactory ?? $this->listing(...))($projectPath);

        try {
            $process->run();
        } catch (ExceptionInterface $exception) {
            return $this->unavailable($projectPath, $exception->getMessage());
        }

        if (!$process->isSuccessful()) {
            return $this->unavailable($projectPath, $process->getErrorOutput());
        }

        $paths = explode("\0", $process->getOutput());
        array_pop($paths);

        return $paths;
    }

    private function listing(string $projectPath): Process
    {
        // `core.fsmonitor=` keeps a hook set in the audited repository's own .git/config from running on this index read
        return new Process(['git', '-c', 'core.fsmonitor=', 'ls-files', '--cached', '--ignored', '--exclude-standard', '-z'], $projectPath);
    }

    /**
     * @return list<string>
     */
    private function unavailable(string $projectPath, string $reason): array
    {
        if ($this->filesystem->exists(\sprintf('%s/.git', $projectPath))) {
            $this->logger->warning('Could not list the files git tracks, a tracked file a .gitignore pattern matches is left out of the scan', [
                'path' => $projectPath,
                'error' => $reason,
            ]);
        }

        return [];
    }
}
