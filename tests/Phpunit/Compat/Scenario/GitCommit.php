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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

use Override;
use Symfony\Component\Process\Process;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner\Workspace;

/**
 * Commits everything the audited project holds, so `--since` and
 * `.gitignore` scenarios see a repository; `$forced` files are added even
 * where a `.gitignore` pattern matches them.
 */
final readonly class GitCommit implements SetupActionInterface
{
    private const string FIXED_DATE = '2026-01-01T00:00:00+00:00';

    /**
     * @param list<string> $forced
     */
    public function __construct(
        private array $forced = [],
    ) {}

    #[Override]
    public function apply(Workspace $workspace): void
    {
        $this->git($workspace, ['init', '--quiet', '--initial-branch=main', '.']);
        $this->git($workspace, ['add', '--all']);

        if ([] !== $this->forced) {
            $this->git($workspace, ['add', '--force', ...$this->forced]);
        }

        $this->git($workspace, ['commit', '--quiet', '--no-gpg-sign', '--message=initial']);
    }

    /**
     * @param list<string> $arguments
     */
    private function git(Workspace $workspace, array $arguments): void
    {
        (new Process(['git', ...$arguments], $workspace->projectDir(), [
            'GIT_AUTHOR_NAME' => 'Compat',
            'GIT_AUTHOR_EMAIL' => 'compat@example.com',
            'GIT_COMMITTER_NAME' => 'Compat',
            'GIT_COMMITTER_EMAIL' => 'compat@example.com',
            'GIT_AUTHOR_DATE' => self::FIXED_DATE,
            'GIT_COMMITTER_DATE' => self::FIXED_DATE,
        ]))->mustRun();
    }
}
