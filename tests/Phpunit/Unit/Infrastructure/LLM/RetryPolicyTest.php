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
        // Pins `< 0.0` boundary — mutation to `<= 0.0` would reject 0.0.
        $retryPolicy = new RetryPolicy(jitterRatio: 0.0);

        self::assertSame(3, $retryPolicy->maxAttempts());
    }

    public function test_jitter_ratio_one_is_accepted(): void
    {
        // Pins `> 1.0` boundary — mutation to `>= 1.0` would reject 1.0.
        $retryPolicy = new RetryPolicy(jitterRatio: 1.0);

        self::assertSame(3, $retryPolicy->maxAttempts());
    }

    public function test_max_attempts_one_is_accepted(): void
    {
        // Pins `< 1` boundary — mutation to `<= 1` would reject 1.
        $retryPolicy = new RetryPolicy(maxAttempts: 1);

        self::assertSame(1, $retryPolicy->maxAttempts());
    }

    public function test_initial_delay_zero_is_accepted(): void
    {
        // Pins `< 0` boundary — mutation to `<= 0` would reject 0.
        $retryPolicy = new RetryPolicy(initialDelayMs: 0, jitterSource: static fn (): float => 0.5);

        self::assertSame(0, $retryPolicy->delayMs(1));
    }

    public function test_backoff_multiplier_one_is_accepted(): void
    {
        // Pins `< 1.0` boundary — mutation to `<= 1.0` would reject 1.0.
        $retryPolicy = new RetryPolicy(
            initialDelayMs: 100,
            backoffMultiplier: 1.0,
            jitterRatio: 0.0,
            jitterSource: static fn (): float => 0.5,
        );

        // With multiplier 1.0, delays do not grow.
        self::assertSame(100, $retryPolicy->delayMs(1));
        self::assertSame(100, $retryPolicy->delayMs(5));
    }

    public function test_constructor_defaults_match_documented_values(): void
    {
        // Pins the default values in the constructor signature — DecrementInteger
        // and IncrementInteger mutations would shift them.
        $retryPolicy = new RetryPolicy(jitterSource: static fn (): float => 0.5);

        self::assertSame(RetryPolicy::DEFAULT_MAX_ATTEMPTS, $retryPolicy->maxAttempts());
        self::assertSame(3, $retryPolicy->maxAttempts());
        // Initial delay 500 × multiplier 2.0 ^ (attempt-1) with jitter midpoint
        self::assertSame(500, $retryPolicy->delayMs(1));
        self::assertSame(1000, $retryPolicy->delayMs(2));
        self::assertSame(2000, $retryPolicy->delayMs(3));
    }

    public function test_default_jitter_source_produces_value_in_range(): void
    {
        // Pins the `mt_rand() / mt_getrandmax()` default jitter source — a
        // mutation to `mt_rand() * mt_getrandmax()` would produce huge values.
        // Without injecting jitter, delay should land within ±20% of the base.
        $retryPolicy = new RetryPolicy(initialDelayMs: 1_000, backoffMultiplier: 1.0, jitterRatio: 0.2);

        // Sample multiple times: every value must be in [800, 1200].
        for ($attempt = 1; $attempt <= 20; ++$attempt) {
            $delay = $retryPolicy->delayMs(1);
            self::assertGreaterThanOrEqual(800, $delay);
            self::assertLessThanOrEqual(1200, $delay);
        }
    }
}
