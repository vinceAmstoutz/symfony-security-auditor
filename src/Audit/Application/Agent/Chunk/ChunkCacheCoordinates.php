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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk;

/**
 * Where a chunk's findings are cached and whether they may be: everything a
 * cache lookup needs of a {@see ChunkContext}, known before its prompts are.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkCacheCoordinates
{
    public function __construct(
        public string $contextKey,
        public bool $cacheable,
    ) {}
}
