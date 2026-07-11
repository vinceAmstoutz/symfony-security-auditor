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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\BackoffSchedule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimitBackoff;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;

final class RetryPolicyTest extends TestCase
{
    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_max_attempts_returns_configured_value(): void
    {
        $retryPolicy = new RetryPolicy(new BackoffSchedule(maxAttempts: 5));

        self::assertSame(5, $retryPolicy->maxAttempts());
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    #[DataProvider('deterministicDelayCases')]
    public function test_delay_grows_geometrically_without_jitter(int $attempt, int $expectedMs): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 100, backoffMultiplier: 2.0, jitterRatio: 0.0),
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

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_jitter_scales_delay_within_configured_bounds(): void
    {
        $retryPolicyLow = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 1000, backoffMultiplier: 1.0, jitterRatio: 0.2),
            jitterSource: static fn (): float => 0.0,
        );
        $retryPolicyHigh = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 1000, backoffMultiplier: 1.0, jitterRatio: 0.2),
            jitterSource: static fn (): float => 1.0,
        );

        self::assertSame(800, $retryPolicyLow->delayMs(1));
        self::assertSame(1200, $retryPolicyHigh->delayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_delay_rounds_low_fraction_down_distinguishing_ceil(): void
    {
        // 100 × (1 + 0.5 × (2×0.744 − 1)) = 124.4 → round 124, ceil 125, floor 124.
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 100, backoffMultiplier: 1.0, jitterRatio: 0.5),
            jitterSource: static fn (): float => 0.744,
        );

        self::assertSame(124, $retryPolicy->delayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_delay_rounds_high_fraction_up_distinguishing_floor(): void
    {
        // 100 × (1 + 0.5 × (2×0.747 − 1)) = 124.7 → round 125, ceil 125, floor 124.
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 100, backoffMultiplier: 1.0, jitterRatio: 0.5),
            jitterSource: static fn (): float => 0.747,
        );

        self::assertSame(125, $retryPolicy->delayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_zero_initial_delay_always_returns_zero(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 0),
            jitterSource: static fn (): float => 0.0,
        );

        self::assertSame(0, $retryPolicy->delayMs(1));
        self::assertSame(0, $retryPolicy->delayMs(3));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_delay_is_clamped_to_max_instead_of_growing_unbounded(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(maxAttempts: 20, initialDelayMs: 500, backoffMultiplier: 2.0, jitterRatio: 0.0),
            jitterSource: static fn (): float => 0.0,
        );

        self::assertSame(300_000, $retryPolicy->delayMs(19));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_delay_stays_clamped_to_max_even_when_the_exponential_term_would_overflow_an_int(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(maxAttempts: 100, initialDelayMs: 500, backoffMultiplier: 2.0, jitterRatio: 0.0),
            jitterSource: static fn (): float => 0.0,
        );

        self::assertSame(300_000, $retryPolicy->delayMs(56));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_invalid_attempt_is_rejected(): void
    {
        $retryPolicy = new RetryPolicy();

        $this->expectException(InvalidRetryConfigurationException::class);
        $this->expectExceptionMessage('attempt must be >= 1, got 0');

        $retryPolicy->delayMs(0);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_invalid_attempt_is_rejected_for_rate_limit_delay(): void
    {
        $retryPolicy = new RetryPolicy();

        $this->expectException(InvalidRetryConfigurationException::class);
        $this->expectExceptionMessage('attempt must be >= 1, got 0');

        $retryPolicy->rateLimitDelayMs(0);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_invalid_max_attempts_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('maxAttempts must be >= 1, got 0');

        new BackoffSchedule(maxAttempts: 0);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_negative_initial_delay_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('initialDelayMs must be >= 0, got -1');

        new BackoffSchedule(initialDelayMs: -1);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_backoff_multiplier_below_one_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('backoffMultiplier must be >= 1.0');

        new BackoffSchedule(backoffMultiplier: 0.5);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_jitter_ratio_outside_zero_one_range_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('jitterRatio must be in [0.0, 1.0]');

        new BackoffSchedule(jitterRatio: 1.5);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_negative_jitter_ratio_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('jitterRatio must be in [0.0, 1.0]');

        new BackoffSchedule(jitterRatio: -0.01);
    }

    public function test_invalid_configuration_messages_format_the_value_with_a_period_regardless_of_the_process_numeric_locale(): void
    {
        $previousLocale = setlocale(\LC_NUMERIC, '0');
        setlocale(\LC_NUMERIC, 'de_DE.UTF-8');

        try {
            $message = '';
            try {
                new BackoffSchedule(backoffMultiplier: 0.5);
            } catch (InvalidArgumentException $invalidArgumentException) {
                $message = $invalidArgumentException->getMessage();
            }
        } finally {
            setlocale(\LC_NUMERIC, false !== $previousLocale ? $previousLocale : 'C');
        }

        self::assertStringContainsString('got 0.500000', $message);
    }

    public function test_low_backoff_multiplier_message_formats_the_value_with_exactly_six_decimals(): void
    {
        $message = '';

        try {
            new BackoffSchedule(backoffMultiplier: 0.5);
        } catch (InvalidArgumentException $invalidArgumentException) {
            $message = $invalidArgumentException->getMessage();
        }

        self::assertSame('backoffMultiplier must be >= 1.0, got 0.500000', $message);
    }

    public function test_out_of_range_jitter_ratio_message_formats_the_value_with_exactly_six_decimals(): void
    {
        $message = '';

        try {
            new BackoffSchedule(jitterRatio: 1.5);
        } catch (InvalidArgumentException $invalidArgumentException) {
            $message = $invalidArgumentException->getMessage();
        }

        self::assertSame('jitterRatio must be in [0.0, 1.0], got 1.500000', $message);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_jitter_ratio_zero_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(new BackoffSchedule(jitterRatio: 0.0));

        self::assertSame(3, $retryPolicy->maxAttempts());
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_jitter_ratio_one_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(new BackoffSchedule(jitterRatio: 1.0));

        self::assertSame(3, $retryPolicy->maxAttempts());
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_max_attempts_one_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(new BackoffSchedule(maxAttempts: 1));

        self::assertSame(1, $retryPolicy->maxAttempts());
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_initial_delay_zero_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(new BackoffSchedule(initialDelayMs: 0), jitterSource: static fn (): float => 0.5);

        self::assertSame(0, $retryPolicy->delayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_backoff_multiplier_one_is_accepted(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 100, backoffMultiplier: 1.0, jitterRatio: 0.0),
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(100, $retryPolicy->delayMs(1));
        self::assertSame(100, $retryPolicy->delayMs(5));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_constructor_defaults_match_documented_values(): void
    {
        $retryPolicy = new RetryPolicy(jitterSource: static fn (): float => 0.5);

        self::assertSame(RetryPolicy::DEFAULT_MAX_ATTEMPTS, $retryPolicy->maxAttempts());
        self::assertSame(3, $retryPolicy->maxAttempts());
        self::assertSame(500, $retryPolicy->delayMs(1));
        self::assertSame(1000, $retryPolicy->delayMs(2));
        self::assertSame(2000, $retryPolicy->delayMs(3));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_rate_limit_delay_uses_its_own_initial_delay(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 500, backoffMultiplier: 2.0, jitterRatio: 0.0),
            new RateLimitBackoff(initialDelayMs: 60_000),
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1));
        self::assertSame(120_000, $retryPolicy->rateLimitDelayMs(2));
        self::assertSame(240_000, $retryPolicy->rateLimitDelayMs(3));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_rate_limit_delay_is_independent_of_regular_delay(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 100, backoffMultiplier: 1.0, jitterRatio: 0.0),
            new RateLimitBackoff(initialDelayMs: 60_000),
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(100, $retryPolicy->delayMs(1));
        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_rate_limit_delay_default_is_at_least_sixty_seconds(): void
    {
        $retryPolicy = new RetryPolicy(jitterSource: static fn (): float => 0.0);

        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_rate_limit_delay_jitter_never_fires_before_the_window_has_elapsed(): void
    {
        $retryPolicyAtFloor = new RetryPolicy(
            new BackoffSchedule(jitterRatio: 0.2),
            new RateLimitBackoff(initialDelayMs: 60_000),
            jitterSource: static fn (): float => 0.0,
        );
        $retryPolicyAtCeiling = new RetryPolicy(
            new BackoffSchedule(jitterRatio: 0.2),
            new RateLimitBackoff(initialDelayMs: 60_000),
            jitterSource: static fn (): float => 1.0,
        );

        self::assertSame(60_000, $retryPolicyAtFloor->rateLimitDelayMs(1));
        self::assertSame(72_000, $retryPolicyAtCeiling->rateLimitDelayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_regular_delay_jitter_remains_symmetric_around_the_base(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(initialDelayMs: 60_000, jitterRatio: 0.2),
            jitterSource: static fn (): float => 0.0,
        );

        self::assertSame(48_000, $retryPolicy->delayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_negative_rate_limit_initial_delay_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('rateLimitInitialDelayMs must be >= 0, got -1');

        new RateLimitBackoff(initialDelayMs: -1);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_server_hint_overrides_exponential_backoff(): void
    {
        $retryPolicy = new RetryPolicy(
            rateLimitBackoff: new RateLimitBackoff(initialDelayMs: 60_000),
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(7_000, $retryPolicy->rateLimitDelayMs(1, serverHintSeconds: 7));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_server_hint_is_clamped_to_maximum(): void
    {
        $retryPolicy = new RetryPolicy(
            rateLimitBackoff: new RateLimitBackoff(maxDelayMs: 300_000),
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(300_000, $retryPolicy->rateLimitDelayMs(1, serverHintSeconds: 3_600));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_server_hint_zero_falls_back_to_exponential(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(backoffMultiplier: 2.0, jitterRatio: 0.0),
            new RateLimitBackoff(initialDelayMs: 60_000),
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1, serverHintSeconds: 0));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_negative_server_hint_falls_back_to_exponential(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(jitterRatio: 0.0),
            new RateLimitBackoff(initialDelayMs: 60_000),
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(60_000, $retryPolicy->rateLimitDelayMs(1, serverHintSeconds: -5));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_negative_rate_limit_max_delay_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('rateLimitMaxDelayMs must be >= 0, got -1');

        new RateLimitBackoff(maxDelayMs: -1);
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_zero_rate_limit_delays_are_accepted_and_clamp_to_zero(): void
    {
        $retryPolicy = new RetryPolicy(
            rateLimitBackoff: new RateLimitBackoff(initialDelayMs: 0, maxDelayMs: 0),
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(0, $retryPolicy->rateLimitDelayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_exponential_delay_is_also_clamped_to_max(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(backoffMultiplier: 10.0, jitterRatio: 0.0),
            new RateLimitBackoff(initialDelayMs: 60_000, maxDelayMs: 120_000),
            jitterSource: static fn (): float => 0.5,
        );

        self::assertSame(120_000, $retryPolicy->rateLimitDelayMs(3));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_rate_limit_delay_rounds_a_high_fraction_up_distinguishing_floor(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(backoffMultiplier: 1.0, jitterRatio: 0.25),
            new RateLimitBackoff(initialDelayMs: 2, maxDelayMs: 300_000),
            jitterSource: static fn (): float => 1.0,
        );

        self::assertSame(3, $retryPolicy->rateLimitDelayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_rate_limit_delay_rounds_a_low_fraction_down_distinguishing_ceil(): void
    {
        $retryPolicy = new RetryPolicy(
            new BackoffSchedule(backoffMultiplier: 1.0, jitterRatio: 0.125),
            new RateLimitBackoff(initialDelayMs: 2, maxDelayMs: 300_000),
            jitterSource: static fn (): float => 1.0,
        );

        self::assertSame(2, $retryPolicy->rateLimitDelayMs(1));
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    public function test_default_jitter_source_produces_value_in_range(): void
    {
        $retryPolicy = new RetryPolicy(new BackoffSchedule(initialDelayMs: 1_000, backoffMultiplier: 1.0, jitterRatio: 0.2));

        for ($attempt = 1; $attempt <= 20; ++$attempt) {
            $delay = $retryPolicy->delayMs(1);
            self::assertGreaterThanOrEqual(800, $delay);
            self::assertLessThanOrEqual(1200, $delay);
        }
    }
}
