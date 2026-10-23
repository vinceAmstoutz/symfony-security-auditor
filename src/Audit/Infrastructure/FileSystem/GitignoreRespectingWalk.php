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
 * Walks one directory with a Finder, with the `.gitignore` files applied as
 * Finder's own `ignoreVCSIgnored()` applies them from that directory when the
 * scan respects them. Finder stops the walk on a `.gitignore` that is not a
 * file, such as a directory a repository commits under that name, or that it
 * cannot read, so the walk of that directory is made again with
 * {@see ReadableGitignores}, which reads the same rules from the same
 * directory and finds none in it: a file the stopped walk already gave comes
 * again, and the scan reads it once and keeps it once.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GitignoreRespectingWalk
{
    public function __construct(
        private bool $respectGitignore,
        private LoggerInterface $logger,
    ) {}

    /**
     * @param string $directory the one directory the finder walks
     *
     * @return Generator<SplFileInfo>
     */
    public function files(Finder $finder, string $directory): Generator
    {
        $readableGitignoreWalk = clone $finder;

        try {
            yield from $finder->ignoreVCSIgnored($this->respectGitignore);
        } catch (RuntimeException) {
            yield from ReadableGitignores::of($directory, $this->logger)->applyTo($readableGitignoreWalk);
        }
    }
}
