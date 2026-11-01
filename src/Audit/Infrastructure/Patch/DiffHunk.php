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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch;

/**
 * One hunk of a unified diff: the lines it expects from line `oldStart` of the
 * file on, and the lines that replace them. A hunk that only adds lines
 * expects none, and `oldStart` is the line they go before.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class DiffHunk
{
    /**
     * @param list<string> $oldLines
     * @param list<string> $newLines
     */
    public function __construct(
        public int $oldStart,
        public array $oldLines,
        public array $newLines,
    ) {}

    public function oldEnd(): int
    {
        return $this->oldStart + \count($this->oldLines) - 1;
    }
}
