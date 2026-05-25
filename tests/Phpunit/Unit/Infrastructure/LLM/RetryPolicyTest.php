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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;

final class RetryPolicyTest extends TestCase
{
    public function test_max_attempts_returns_configured_value(): void
    {
        $retryPolicy = new RetryPolicy(maxAttempts: 5);

        self::assertSame(5, $retryPolicy->maxAttempts());
    }

    #[DataProvider('deterministicDelayCases')]
    public function test_delay_grows_geometrically_without_jitter(int $attempt, int $expectedMs): void
    {
        $retryPolicy = new RetryPolicy(
            initialDelayMs: 100,
            backoffMultiplier: 2.0,
            jitterRatio: 0.0,
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame($expectedMs, $retryPolicy->delayMs($attempt));
    }

    /** @return iterable<string, array{int, int}> */
    public static function deterministicDelayCases(): iterable
    {
        yield 'first retry uses initial delay' => [1, 100];
        yield 'second retry doubles' => [2, 200];
        yield 'third retry quadruples' => [3, 400];
        yield 'fourth retry octuples' => [4, 800];
    }

    public function test_jitter_scales_delay_within_configured_bounds(): void
    {
        $retryPolicyLow = new RetryPolicy(
            initialDelayMs: 1000,
            backoffMultiplier: 1.0,
            jitterRatio: 0.2,
            jitterSource: static fn (): float => 0.0,
        );
        $retryPolicyHigh = new RetryPolicy(
            initialDelayMs: 1000,
            backoffMultiplier: 1.0,
            jitterRatio: 0.2,
            jitterSource: static fn (): float => 1.0,
        );

        self::assertSame(800, $retryPolicyLow->delayMs(1));
        self::assertSame(1200, $retryPolicyHigh->delayMs(1));
    }

    public function test_delay_rounds_low_fraction_down_distinguishing_ceil(): void
    {
        // 100 × (1 + 0.5 × (2×0.744 − 1)) = 124.4 → round 124, ceil 125, floor 124.
        $retryPolicy = new RetryPolicy(
            initialDelayMs: 100,
            backoffMultiplier: 1.0,
            jitterRatio: 0.5,
            jitterSource: static fn (): float => 0.744,
        );

        self::assertSame(124, $retryPolicy->delayMs(1));
    }

    public function test_delay_rounds_high_fraction_up_distinguishing_floor(): void
    {
        // 100 × (1 + 0.5 × (2×0.747 − 1)) = 124.7 → round 125, ceil 125, floor 124.
        $retryPolicy = new RetryPolicy(
            initialDelayMs: 100,
            backoffMultiplier: 1.0,
            jitterRatio: 0.5,
            jitterSource: static fn (): float => 0.747,
        );

        self::assertSame(125, $retryPolicy->delayMs(1));
    }

    public function test_zero_initial_delay_always_returns_zero(): void
    {
        $retryPolicy = new RetryPolicy(
            initialDelayMs: 0,
            jitterSource: static fn (): float => 0.0,
        );

        self::assertSame(0, $retryPolicy->delayMs(1));
        self::assertSame(0, $retryPolicy->delayMs(3));
    }

    public function test_invalid_attempt_is_rejected(): void
    {
        $retryPolicy = new RetryPolicy();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('attempt must be >= 1, got 0');

        $retryPolicy->delayMs(0);
    }

    public function test_invalid_attempt_is_rejected_for_rate_limit_delay(): void
    {
        $retryPolicy = new RetryPolicy();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('attempt must be >= 1, got 0');

        $retryPolicy->rateLimitDelayMs(0);
    }

    public function test_invalid_max_attempts_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('maxAttempts must be >= 1, got 0');

        new RetryPolicy(maxAttempts: 0);
    }

    public function test_negative_initial_delay_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('initialDelayMs must be >= 0, got -1');

        new RetryPolicy(initialDelayMs: -1);
    }

    public function test_backoff_multiplier_below_one_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('backoffMultiplier must be >= 1.0');

        new RetryPolicy(backoffMultiplier: 0.5);
    }

    public function test_jitter_ratio_outside_zero_one_range_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('jitterRatio must be in [0.0, 1.0]');

        new RetryPolicy(jitterRatio: 1.5);
    }

    public function test_negative_jitter_ratio_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('jitterRatio must be in [0.0, 1.0]');

        new RetryPolicy(jitterRatio: -0.01);
    }

    public function test_jitter_ratio_zero_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(jitterRatio: 0.0);

        self::assertSame(3, $retryPolicy->maxAttempts());
    }

    public function test_jitter_ratio_one_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(jitterRatio: 1.0);

        self::assertSame(3, $retryPolicy->maxAttempts());
    }

    public function test_max_attempts_one_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(maxAttempts: 1);

        self::assertSame(1, $retryPolicy->maxAttempts());
    }

    public function test_initial_delay_zero_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(initialDelayMs: 0, jitterSource: static fn (): float => 0.5);

        self::assertSame(0, $retryPolicy->delayMs(1));
    }

    public function test_backoff_multiplier_one_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(
            initialDelayMs: 100,
            backoffMultiplier: 1.0,
            jitterRatio: 0.0,
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(100, $retryPolicy->delayMs(1));
        self::assertSame(100, $retryPolicy->delayMs(5));
    }

    public function test_constructor_defaults_match_documented_values(): void
    {
        $retryPolicy = new RetryPolicy(jitterSource: static fn (): float => 0.5);

        self::assertSame(RetryPolicy::DEFAULT_MAX_ATTEMPTS, $retryPolicy->maxAttempts());
        self::assertSame(3, $retryPolicy->maxAttempts());
        self::assertSame(500, $retryPolicy->delayMs(1));
        self::assertSame(1000, $retryPolicy->delayMs(2));
        self::assertSame(2000, $retryPolicy->delayMs(3));
    }

    public function test_rate_limit_delay_uses_its_own_initial_delay(): void
    {
        $retryPolicy = new RetryPolicy(
            initialDelayMs: 500,
            backoffMultiplier: 2.0,
            jitterRatio: 0.0,
            rateLimitInitialDelayMs: 60_000,
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1));
        self::assertSame(120_000, $retryPolicy->rateLimitDelayMs(2));
        self::assertSame(240_000, $retryPolicy->rateLimitDelayMs(3));
    }

    public function test_rate_limit_delay_is_independent_of_regular_delay(): void
    {
        $retryPolicy = new RetryPolicy(
            initialDelayMs: 100,
            backoffMultiplier: 1.0,
            jitterRatio: 0.0,
            rateLimitInitialDelayMs: 60_000,
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(100, $retryPolicy->delayMs(1));
        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1));
    }

    public function test_rate_limit_delay_default_is_sixty_seconds(): void
    {
        $retryPolicy = new RetryPolicy(jitterSource: static fn (): float => 0.5);

        self::assertSame(RetryPolicy::DEFAULT_RATE_LIMIT_DELAY_MS, 60_000);
        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1));
    }

    public function test_negative_rate_limit_initial_delay_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('rateLimitInitialDelayMs must be >= 0, got -1');

        new RetryPolicy(rateLimitInitialDelayMs: -1);
    }

    public function test_server_hint_overrides_exponential_backoff(): void
    {
        $retryPolicy = new RetryPolicy(
            rateLimitInitialDelayMs: 60_000,
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(7_000, $retryPolicy->rateLimitDelayMs(1, serverHintSeconds: 7));
    }

    public function test_server_hint_is_clamped_to_maximum(): void
    {
        $retryPolicy = new RetryPolicy(
            rateLimitMaxDelayMs: 300_000,
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(300_000, $retryPolicy->rateLimitDelayMs(1, serverHintSeconds: 3_600));
    }

    public function test_server_hint_zero_falls_back_to_exponential(): void
    {
        $retryPolicy = new RetryPolicy(
            backoffMultiplier: 2.0,
            jitterRatio: 0.0,
            rateLimitInitialDelayMs: 60_000,
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1, serverHintSeconds: 0));
    }

    public function test_negative_server_hint_falls_back_to_exponential(): void
    {
        $retryPolicy = new RetryPolicy(
            jitterRatio: 0.0,
            rateLimitInitialDelayMs: 60_000,
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1, serverHintSeconds: -5));
    }

    public function test_negative_rate_limit_max_delay_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('rateLimitMaxDelayMs must be >= 0, got -1');

        new RetryPolicy(rateLimitMaxDelayMs: -1);
    }

    public function test_exponential_delay_is_also_clamped_to_max(): void
    {
        $retryPolicy = new RetryPolicy(
            backoffMultiplier: 10.0,
            jitterRatio: 0.0,
            rateLimitInitialDelayMs: 60_000,
            rateLimitMaxDelayMs: 120_000,
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(120_000, $retryPolicy->rateLimitDelayMs(3));
    }

    public function test_default_jitter_source_produces_value_in_range(): void
    {
        $retryPolicy = new RetryPolicy(initialDelayMs: 1_000, backoffMultiplier: 1.0, jitterRatio: 0.2);

        for ($attempt = 1; $attempt <= 20; ++$attempt) {
            $delay = $retryPolicy->delayMs(1);
            self::assertGreaterThanOrEqual(800, $delay);
            self::assertLessThanOrEqual(1200, $delay);
        }
    }
}
