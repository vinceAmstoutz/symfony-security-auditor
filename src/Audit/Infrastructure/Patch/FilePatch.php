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
 * The hunks a unified diff applies to one file, named by its path relative to
 * the project root.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FilePatch
{
    /**
     * @param non-empty-list<DiffHunk> $hunks
     */
    public function __construct(
        public string $path,
        public array $hunks,
    ) {}
}
