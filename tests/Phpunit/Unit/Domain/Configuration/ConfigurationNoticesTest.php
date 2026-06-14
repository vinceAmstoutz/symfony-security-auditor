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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\ConfigurationNotices;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\LLMConfiguration;

final class ConfigurationNoticesTest extends TestCase
{
    public function test_no_notices_for_the_default_configuration(): void
    {
        self::assertSame([], ConfigurationNotices::of($this->audit(reviewerBatchSize: 1), $this->llm()));
    }

    public function test_batched_reviews_emit_no_notice_now_that_the_cache_covers_them(): void
    {
        self::assertSame([], ConfigurationNotices::of($this->audit(reviewerBatchSize: 5), $this->llm()));
    }

    public function test_escalation_with_a_cheap_model_equal_to_the_attacker_model_emits_a_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, escalationEnabled: true, escalationCheapModel: 'claude-opus-4-8'),
            $this->llm('claude-opus-4-8'),
        );

        self::assertCount(1, $notices);
        self::assertStringContainsString('escalation', $notices[0]);
        self::assertStringContainsString('audit.escalation.cheap_model', $notices[0]);
    }

    public function test_escalation_with_a_genuinely_cheaper_model_emits_no_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, escalationEnabled: true, escalationCheapModel: 'claude-haiku-4-5-20251001'),
            $this->llm('claude-opus-4-8'),
        );

        self::assertSame([], $notices);
    }

    public function test_escalation_falling_back_to_the_attacker_model_emits_a_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, escalationEnabled: true),
            $this->llm('claude-opus-4-8'),
        );

        self::assertCount(1, $notices);
        self::assertStringContainsString('escalation', $notices[0]);
    }

    public function test_disabled_escalation_emits_no_notice_even_when_models_match(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, escalationEnabled: false),
            $this->llm('claude-opus-4-8'),
        );

        self::assertSame([], $notices);
    }

    public function test_reviewer_concurrency_with_tools_enabled_emits_a_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, reviewerMaxConcurrent: 4, reviewerToolsEnabled: true),
            $this->llm(),
        );

        self::assertCount(1, $notices);
        self::assertStringContainsString('audit.reviewer_max_concurrent', $notices[0]);
        self::assertStringContainsString('audit.reviewer_tools_enabled', $notices[0]);
    }

    public function test_reviewer_concurrency_without_tools_emits_no_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, reviewerMaxConcurrent: 4, reviewerToolsEnabled: false),
            $this->llm(),
        );

        self::assertSame([], $notices);
    }

    public function test_attacker_concurrency_with_tools_enabled_emits_a_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, attackerMaxConcurrent: 4, toolsEnabled: true, structuredCollection: true),
            $this->llm(),
        );

        self::assertCount(1, $notices);
        self::assertStringContainsString('audit.attacker_max_concurrent', $notices[0]);
    }

    public function test_attacker_concurrency_with_structured_collection_off_emits_a_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, attackerMaxConcurrent: 4, toolsEnabled: false, structuredCollection: false),
            $this->llm(),
        );

        self::assertCount(1, $notices);
        self::assertStringContainsString('audit.structured_collection', $notices[0]);
    }

    public function test_attacker_concurrency_in_structured_toolless_mode_emits_no_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, attackerMaxConcurrent: 4, toolsEnabled: false, structuredCollection: true),
            $this->llm(),
        );

        self::assertSame([], $notices);
    }

    public function test_reviewer_concurrency_of_one_with_tools_emits_no_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, reviewerMaxConcurrent: 1, reviewerToolsEnabled: true),
            $this->llm(),
        );

        self::assertSame([], $notices);
    }

    public function test_attacker_concurrency_of_one_with_tools_emits_no_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(reviewerBatchSize: 1, attackerMaxConcurrent: 1, toolsEnabled: true),
            $this->llm(),
        );

        self::assertSame([], $notices);
    }

    public function test_multiple_simultaneous_footguns_each_emit_their_own_notice(): void
    {
        $notices = ConfigurationNotices::of(
            $this->audit(
                reviewerBatchSize: 5,
                reviewerMaxConcurrent: 4,
                reviewerToolsEnabled: true,
                attackerMaxConcurrent: 4,
                toolsEnabled: true,
            ),
            $this->llm(),
        );

        self::assertCount(2, $notices);
        self::assertStringContainsString('audit.reviewer_max_concurrent', $notices[0]);
        self::assertStringContainsString('audit.attacker_max_concurrent', $notices[1]);
    }

    private function audit(
        int $reviewerBatchSize,
        bool $escalationEnabled = false,
        ?string $escalationCheapModel = null,
        int $reviewerMaxConcurrent = 1,
        bool $reviewerToolsEnabled = false,
        int $attackerMaxConcurrent = 1,
        bool $toolsEnabled = true,
        bool $structuredCollection = true,
    ): AuditExecutionConfiguration {
        return new AuditExecutionConfiguration(
            maxIterations: 3,
            minConfidence: 0.6,
            reviewerBatchSize: $reviewerBatchSize,
            toolsEnabled: $toolsEnabled,
            maxToolIterations: 8,
            reviewerToolsEnabled: $reviewerToolsEnabled,
            reviewerMaxConcurrent: $reviewerMaxConcurrent,
            attackerMaxConcurrent: $attackerMaxConcurrent,
            escalationEnabled: $escalationEnabled,
            escalationCheapModel: $escalationCheapModel,
            structuredCollection: $structuredCollection,
        );
    }

    private function llm(string $model = 'claude-opus-4-8'): LLMConfiguration
    {
        return new LLMConfiguration($model, null, null);
    }
}
