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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\RateLimit;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;

final class NullRateLimiterTest extends TestCase
{
    public function test_acquire_record_and_pause_are_all_no_ops(): void
    {
        $nullRateLimiter = new NullRateLimiter();
        $beforeNs = hrtime(true);

        $nullRateLimiter->acquire(estimatedInputTokens: 1_000_000);
        $nullRateLimiter->record(inputTokens: 50_000, outputTokens: 10_000);
        $nullRateLimiter->pauseUntil(new DateTimeImmutable('+1 hour'));

        $elapsedMs = (hrtime(true) - $beforeNs) / 1_000_000;
        self::assertLessThan(50, $elapsedMs, 'NullRateLimiter must never block');
    }
}
