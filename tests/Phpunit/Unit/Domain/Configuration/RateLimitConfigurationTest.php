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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Configuration;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\RateLimitConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRateLimitConfigurationException;

final class RateLimitConfigurationTest extends TestCase
{
    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_all_null_means_disabled(): void
    {
        $rateLimitConfiguration = new RateLimitConfiguration(null, null, null);

        self::assertFalse($rateLimitConfiguration->isEnabled());
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_any_dimension_set_means_enabled(): void
    {
        self::assertTrue((new RateLimitConfiguration(1, null, null))->isEnabled());
        self::assertTrue((new RateLimitConfiguration(null, 1, null))->isEnabled());
        self::assertTrue((new RateLimitConfiguration(null, null, 1))->isEnabled());
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_zero_requests_per_minute_rejected(): void
    {
        $this->expectException(InvalidRateLimitConfigurationException::class);
        $this->expectExceptionMessage('requestsPerMinute must be >= 1 or null, got 0');

        new RateLimitConfiguration(0, null, null);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_zero_input_tokens_per_minute_rejected(): void
    {
        $this->expectException(InvalidRateLimitConfigurationException::class);
        $this->expectExceptionMessage('inputTokensPerMinute must be >= 1 or null, got 0');

        new RateLimitConfiguration(null, 0, null);
    }

    /**
     * @throws InvalidRateLimitConfigurationException
     */
    public function test_zero_output_tokens_per_minute_rejected(): void
    {
        $this->expectException(InvalidRateLimitConfigurationException::class);
        $this->expectExceptionMessage('outputTokensPerMinute must be >= 1 or null, got 0');

        new RateLimitConfiguration(null, null, 0);
    }
}
