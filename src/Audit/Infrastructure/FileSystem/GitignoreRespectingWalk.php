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

use Generator;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Finder\SplFileInfo;

/**
 * Walks a Finder with the project's `.gitignore` files applied when the scan
 * respects them. A `.gitignore` that is not a file, which stops Finder's
 * `ignoreVCSIgnored()`, holds no rule: the walk starts again through
 * {@see ReadableGitignores} and may yield a file twice.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class GitignoreRespectingWalk
{
    public function __construct(
        private bool $respectGitignore,
        private LoggerInterface $logger,
    ) {}

    /**
     * @return Generator<SplFileInfo>
     */
    public function files(Finder $finder, string $projectPath): Generator
    {
        $readableGitignoreWalk = clone $finder;

        try {
            yield from $finder->ignoreVCSIgnored($this->respectGitignore);
        } catch (RuntimeException) {
            $readableGitignores = ReadableGitignores::of($projectPath, $this->logger);

            yield from $readableGitignoreWalk->filter(static fn (SplFileInfo $splFile): bool => !$readableGitignores->ignore($splFile));
        }
    }
}
