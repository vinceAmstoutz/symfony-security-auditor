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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

/**
 * The code contexts of the cache misses and those to cache their verdicts
 * under, empty when the cache is bypassed.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReviewCacheBuckets
{
    /**
     * @param array<string, string> $codeContexts
     * @param array<string, string> $cacheContexts
     */
    public function __construct(
        public array $codeContexts,
        public array $cacheContexts,
    ) {}
}
