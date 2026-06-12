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
 * The fully-assembled attacker prompt for a single chunk, plus the cache key
 * and cacheability derived from the cross-iteration context.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkContext
{
    public function __construct(
        public string $systemPrompt,
        public string $userMessage,
        public string $contextKey,
        public bool $cacheable,
    ) {}
}
