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
use InvalidArgumentException;
use Override;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use RuntimeException;
use Symfony\Component\Clock\MockClock;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\RateLimitConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RateLimitRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\TokenBucketRateLimiter;

final class TokenBucketRateLimiterTest extends TestCase
{
    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_acquire_returns_immediately_when_capacity_available(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 10,
                inputTokensPerMinute: 50_000,
                outputTokensPerMinute: 10_000,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 1_000);

        self::assertSame([], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_acquire_sleeps_until_next_window_when_rpm_exhausted(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 2,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 10);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 10);
        // 2 requests used. Advance partway then acquire again — should sleep until 12:01:00.
        $mockClock->modify('+30 seconds');
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 10);

        self::assertSame([30_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_acquire_sleeps_when_input_tokens_would_exceed_window(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 100,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 60);

        $mockClock->modify('+10 seconds');
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 60); // total would be 120 > 100 — sleeps to next minute (50s remain).

        self::assertSame([50_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_window_resets_when_minute_elapses(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 1,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 10);

        $mockClock->modify('+61 seconds');
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 10);

        self::assertSame([], $sleeper->sleepsMs, 'fresh window should not require sleeping');
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_record_reconciles_input_estimate_against_actual(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 100,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        // Estimate 60 then learn actual was 30 — frees 30 tokens, next 70 should fit.
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 60);
        $tokenBucketRateLimiter->record(inputTokens: 30, outputTokens: 0);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 70);

        self::assertSame([], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_output_token_exhaustion_blocks_next_acquire(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: null,
                outputTokensPerMinute: 100,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->record(inputTokens: 0, outputTokens: 100);
        // exhaust OTPM
        $mockClock->modify('+10 seconds');
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0); // blocked until window reset at 12:01:00 (50s away).

        self::assertSame([50_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_output_under_quota_does_not_block(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: null,
                outputTokensPerMinute: 100,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->record(inputTokens: 0, outputTokens: 80);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0); // 80 < 100 — fits.

        self::assertSame([], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_pause_until_blocks_acquire_until_target(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 100,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->pauseUntil(new DateTimeImmutable('2026-01-01T12:00:45+00:00'));
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([45_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_pause_resumes_into_capacity_check_and_consumes_quota(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 1,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->pauseUntil(new DateTimeImmutable('2026-01-01T12:00:30+00:00'));
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        // First sleep = pause (30s), second = window wait (30s remaining).
        self::assertSame([30_000, 30_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_pause_spanning_a_window_boundary_resets_the_window_before_reserving(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 1,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->pauseUntil(new DateTimeImmutable('2026-01-01T12:01:05+00:00'));
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        // The pause sleep alone (65s) lands the clock in a fresh window, so the
        // re-evaluated window reset frees the exhausted RPM slot — no second sleep.
        self::assertSame([65_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_pause_until_in_the_past_does_not_block(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 100,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->pauseUntil(new DateTimeImmutable('2025-12-31T23:00:00+00:00'));
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([], $sleeper->sleepsMs);
    }

    public function test_construction_throws_when_all_dimensions_null(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('TokenBucketRateLimiter requires at least one rate-limit dimension; wire NullRateLimiter for fully-disabled config.');

        new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_estimate_larger_than_window_throws(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 100,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $this->expectException(RateLimitRequestTooLargeException::class);
        $this->expectExceptionMessage('estimated input tokens (200) exceed window capacity (100)');

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 200);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_negative_estimate_is_rejected(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 100,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('estimatedInputTokens must be >= 0, got -1');

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: -1);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_record_accumulates_output_across_multiple_calls(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: null,
                outputTokensPerMinute: 100,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        // Two record calls with 50 output each must accumulate to 100 (not
        // overwrite each other), so a third acquire is blocked by OTPM.
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->record(inputTokens: 0, outputTokens: 50);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->record(inputTokens: 0, outputTokens: 50);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([60_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_record_zero_output_does_not_increment_used(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: null,
                outputTokensPerMinute: 1,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        // Recording zero output must leave outputTokensUsed at 0 — the next
        // acquire must succeed under OTPM=1 without sleeping.
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->record(inputTokens: 0, outputTokens: 0);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_post_reset_request_count_starts_at_zero(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 2,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        $mockClock->modify('+61 seconds'); // window expires; new window starts at 12:01:00, ends at 12:02:00 → 59s remaining
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0); // triggers reset, requestsUsed=1
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0); // requestsUsed=2
        // Third acquire in the new window must block: requestsUsed must
        // have started at 0 post-reset (not -1), so cap is hit here.
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([59_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_post_reset_input_count_starts_at_zero(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 10,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 10);

        $mockClock->modify('+61 seconds'); // window expires; 59s remain in new window
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 10); // reset, inputTokensUsed becomes 10
        // The next single-token acquire would only fit if inputTokensUsed
        // started at exactly 0 post-reset (10 + 1 > 10 → block).
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 1);

        self::assertSame([59_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_post_reset_output_count_starts_at_zero(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: null,
                outputTokensPerMinute: 10,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->record(inputTokens: 0, outputTokens: 10);
        // fill OTPM
        $mockClock->modify('+61 seconds'); // window expires; 59s remain in new window
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0); // reset, outputTokensUsed=0
        $tokenBucketRateLimiter->record(inputTokens: 0, outputTokens: 10); // bucket=10 now
        // outputTokensUsed must be exactly 10 (not 9): next acquire blocks.
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([59_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_acquire_accumulates_input_tokens_across_calls(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 15,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 5);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 10);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 5);

        self::assertSame([60_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_record_reconcile_adds_actual_input_to_bucket(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 10,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 5);
        $tokenBucketRateLimiter->record(inputTokens: 5, outputTokens: 0);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 6);

        self::assertSame([60_000], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_concurrent_acquires_are_each_reconciled_against_their_own_estimate(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 100,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        // A batch window acquires for every request before resolving any of
        // them, so two reservations are pending simultaneously here.
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 40);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 50);
        // Reconciling in dispatch order must credit each record() against
        // its own estimate (40, then 50) — not the last-seen estimate for
        // both, which would overcharge the bucket by the first estimate.
        $tokenBucketRateLimiter->record(inputTokens: 20, outputTokens: 0);
        $tokenBucketRateLimiter->record(inputTokens: 30, outputTokens: 0);

        // Correctly reconciled usage is 20 + 30 = 50, leaving room for 45
        // more within the ITPM=100 cap; the pre-fix formula left the bucket
        // at 90, which would block this acquire.
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 45);

        self::assertSame([], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_record_zero_input_uses_reconciled_value_not_pending_estimate(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 5,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 5);
        $tokenBucketRateLimiter->record(inputTokens: 0, outputTokens: 0);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 5);

        self::assertSame([], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_consecutive_records_without_acquire_use_zeroed_pending_estimate(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: null,
                inputTokensPerMinute: 10,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);
        $tokenBucketRateLimiter->record(inputTokens: 5, outputTokens: 0);
        $tokenBucketRateLimiter->record(inputTokens: 5, outputTokens: 0);
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_ms_until_rounds_sub_millisecond_delta_up_to_one(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00.000500+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 1,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        // Sub-millisecond pause: now = 12:00:00.000500, paused = 12:00:00.000700.
        // 200µs gap must round up to exactly 1ms (proves max(1, ...) clamp).
        $tokenBucketRateLimiter->pauseUntil(new DateTimeImmutable('2026-01-01T12:00:00.000700+00:00'));
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([1], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_ms_until_rounds_exact_one_millisecond_delta_to_one(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00.000000+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 1,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        // Exact 1ms (1000µs) delta must produce exactly 1ms — verifies the
        // ceil-equivalent integer math doesn't over-add a millisecond.
        $tokenBucketRateLimiter->pauseUntil(new DateTimeImmutable('2026-01-01T12:00:00.001000+00:00'));
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([1], $sleeper->sleepsMs);
    }

    /**
     * @throws RateLimitRequestTooLargeException
     */
    public function test_ms_until_rounds_just_over_one_millisecond_delta_up_to_two(): void
    {
        $mockClock = new MockClock('2026-01-01T12:00:00.000000+00:00');
        $sleeper = $this->createRecordingSleeper($mockClock);

        $tokenBucketRateLimiter = new TokenBucketRateLimiter(
            rateLimitConfiguration: new RateLimitConfiguration(
                requestsPerMinute: 1,
                inputTokensPerMinute: null,
                outputTokensPerMinute: null,
            ),
            clock: $this->boundedClock($mockClock),
            sleeper: $sleeper,
        );

        // 1.001ms (1001µs) delta must round up to exactly 2ms — proves the
        // ceil-equivalent +999 offset captures the leftover microsecond.
        $tokenBucketRateLimiter->pauseUntil(new DateTimeImmutable('2026-01-01T12:00:00.001001+00:00'));
        $tokenBucketRateLimiter->acquire(estimatedInputTokens: 0);

        self::assertSame([2], $sleeper->sleepsMs);
    }

    private function boundedClock(ClockInterface $clock): ClockInterface
    {
        return new class($clock, 50) implements ClockInterface {
            private int $calls = 0;

            public function __construct(
                private readonly ClockInterface $clock,
                private readonly int $maxCalls,
            ) {}

            #[Override]
            public function now(): DateTimeImmutable
            {
                if (++$this->calls > $this->maxCalls) {
                    throw new RuntimeException(\sprintf('Clock queried %d times — acquire() never terminated (a mutation removed a loop-exit branch).', $this->calls));
                }

                return DateTimeImmutable::createFromInterface($this->clock->now());
            }
        };
    }

    /**
     * @return SleeperInterface&object{sleepsMs: list<int>}
     */
    private function createRecordingSleeper(MockClock $mockClock): SleeperInterface
    {
        return new class($mockClock) implements SleeperInterface {
            /** @var list<int> */
            public array $sleepsMs = [];

            public function __construct(private readonly MockClock $mockClock) {}

            #[Override]
            public function sleep(int $milliseconds): void
            {
                $this->sleepsMs[] = $milliseconds;
                $this->mockClock->sleep($milliseconds / 1_000);
            }
        };
    }
}
