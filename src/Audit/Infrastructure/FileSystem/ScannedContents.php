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
use Symfony\Component\Filesystem\Path;

/**
 * The content of each file a scan read, by its path, as the scanned file
 * holds it: a file two scanned paths reach, or two scans of one run, is read
 * and scrubbed once, and its content is held once.
 *
 * Mutable by design: it keeps what was read across the files of a scan, or
 * the scans of one run, so it opts out of the final readonly rule as a
 * stateful collaborator (see .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class ScannedContents
{
    /** @var array<string, string> */
    private array $contents = [];

    /**
     * @param Closure(): string $readAndScrub what the scanned file holds, asked for the first time the file is reached
     */
    public function of(string $absolutePath, Closure $readAndScrub): string
    {
        return $this->contents[Path::canonicalize($absolutePath)] ??= $readAndScrub();
    }
}
