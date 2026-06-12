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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\AuditExecutionConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\CacheConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\ConfigurationNotices;

final class ConfigurationNoticesTest extends TestCase
{
    public function test_no_notices_for_the_default_configuration(): void
    {
        self::assertSame([], ConfigurationNotices::of($this->cache(enabled: true), $this->audit(reviewerBatchSize: 1)));
    }

    public function test_batched_reviews_with_the_cache_enabled_emit_the_verdict_cache_notice(): void
    {
        $notices = ConfigurationNotices::of($this->cache(enabled: true), $this->audit(reviewerBatchSize: 5));

        self::assertCount(1, $notices);
        self::assertStringContainsString('reviewer-verdict cache', $notices[0]);
        self::assertStringContainsString('audit.reviewer_batch_size', $notices[0]);
    }

    public function test_batched_reviews_with_the_cache_disabled_emit_no_notice(): void
    {
        self::assertSame([], ConfigurationNotices::of($this->cache(enabled: false), $this->audit(reviewerBatchSize: 5)));
    }

    public function test_sequential_reviews_with_the_cache_enabled_emit_no_notice(): void
    {
        self::assertSame([], ConfigurationNotices::of($this->cache(enabled: true), $this->audit(reviewerBatchSize: 1)));
    }

    private function cache(bool $enabled): CacheConfiguration
    {
        return new CacheConfiguration(enabled: $enabled, dir: '/tmp/cache', promptCaching: true);
    }

    private function audit(int $reviewerBatchSize): AuditExecutionConfiguration
    {
        return new AuditExecutionConfiguration(
            maxIterations: 3,
            minConfidence: 0.6,
            reviewerBatchSize: $reviewerBatchSize,
            toolsEnabled: true,
            maxToolIterations: 8,
        );
    }
}
