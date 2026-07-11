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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Review;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ConcurrentReviewBatch;

final class ConcurrentReviewBatchTest extends TestCase
{
    public function test_code_context_for_cache_is_null_when_the_cache_is_bypassed(): void
    {
        $concurrentReviewBatch = new ConcurrentReviewBatch([], [], [], [], [0 => 'ctx'], bypassCache: true);

        self::assertNull($concurrentReviewBatch->codeContextForCache(0));
    }

    public function test_code_context_for_cache_returns_the_context_when_the_cache_is_active(): void
    {
        $concurrentReviewBatch = new ConcurrentReviewBatch([], [], [], [], [0 => 'ctx'], bypassCache: false);

        self::assertSame('ctx', $concurrentReviewBatch->codeContextForCache(0));
    }
}
