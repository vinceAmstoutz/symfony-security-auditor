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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\AuditExecutionConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditExecutionConfigurationException;

final class AuditExecutionConfigurationTest extends TestCase
{
    /**
     * A computed `min_confidence` (e.g. `fdiv($x, $y)` with `$y = 0`, a
     * common "safe division" idiom in a PHP-format config file) can produce
     * `NAN`, which is never `>=` any real confidence value —
     * `AuditOrchestrator::passesConfidenceFloor()`'s `$confidence >=
     * $minConfidence` check would then silently drop every finding on every
     * run. `NAN` also bypasses the TreeBuilder's `min(0.0)`/`max(1.0)`
     * bounds, since both comparisons are false against `NAN`.
     *
     * @throws InvalidAuditExecutionConfigurationException
     */
    public function test_it_rejects_a_nan_min_confidence(): void
    {
        $this->expectException(InvalidAuditExecutionConfigurationException::class);
        $this->expectExceptionMessage('minConfidence must be finite and within 0.0-1.0, got NAN');

        new AuditExecutionConfiguration(
            maxIterations: 3,
            minConfidence: \NAN,
            reviewerBatchSize: 5,
            toolsEnabled: true,
            maxToolIterations: 5,
        );
    }

    /**
     * A positive-infinite `min_confidence` (e.g. `fdiv(1, 0)` in a computed
     * config value) is non-finite, so it is rejected the same way `NAN` is,
     * and rendered as an explicit `INF` literal rather than coerced from the
     * raw float (which PHP 8.5 warns about).
     *
     * @throws InvalidAuditExecutionConfigurationException
     */
    public function test_it_rejects_a_positive_infinite_min_confidence(): void
    {
        $this->expectException(InvalidAuditExecutionConfigurationException::class);
        $this->expectExceptionMessage('minConfidence must be finite and within 0.0-1.0, got INF');

        new AuditExecutionConfiguration(
            maxIterations: 3,
            minConfidence: \INF,
            reviewerBatchSize: 5,
            toolsEnabled: true,
            maxToolIterations: 5,
        );
    }

    /**
     * @throws InvalidAuditExecutionConfigurationException
     */
    public function test_it_rejects_a_negative_infinite_min_confidence(): void
    {
        $this->expectException(InvalidAuditExecutionConfigurationException::class);
        $this->expectExceptionMessage('minConfidence must be finite and within 0.0-1.0, got -INF');

        new AuditExecutionConfiguration(
            maxIterations: 3,
            minConfidence: -\INF,
            reviewerBatchSize: 5,
            toolsEnabled: true,
            maxToolIterations: 5,
        );
    }

    /**
     * @throws InvalidAuditExecutionConfigurationException
     */
    #[DataProvider('effectiveLeanModeCases')]
    public function test_effective_static_prescan_lean_mode_requires_the_prescanner_to_be_enabled(bool $leanMode, bool $preScanEnabled, bool $expected): void
    {
        $auditExecutionConfiguration = new AuditExecutionConfiguration(
            maxIterations: 3,
            minConfidence: 0.6,
            reviewerBatchSize: 5,
            toolsEnabled: true,
            maxToolIterations: 5,
            staticPreScanEnabled: $preScanEnabled,
            staticPreScanLeanMode: $leanMode,
        );

        self::assertSame($expected, $auditExecutionConfiguration->effectiveStaticPreScanLeanMode());
    }

    /** @return iterable<string, array{bool, bool, bool}> */
    public static function effectiveLeanModeCases(): iterable
    {
        yield 'lean on, prescan on' => [true, true, true];
        yield 'lean on, prescan off' => [true, false, false];
        yield 'lean off, prescan on' => [false, true, false];
        yield 'lean off, prescan off' => [false, false, false];
    }

    /**
     * @throws InvalidAuditExecutionConfigurationException
     */
    public function test_it_rejects_a_min_confidence_above_one(): void
    {
        $this->expectException(InvalidAuditExecutionConfigurationException::class);
        $this->expectExceptionMessage('minConfidence must be finite and within 0.0-1.0, got 1.5');

        new AuditExecutionConfiguration(
            maxIterations: 3,
            minConfidence: 1.5,
            reviewerBatchSize: 5,
            toolsEnabled: true,
            maxToolIterations: 5,
        );
    }

    /**
     * @throws InvalidAuditExecutionConfigurationException
     */
    public function test_it_rejects_a_negative_min_confidence(): void
    {
        $this->expectException(InvalidAuditExecutionConfigurationException::class);
        $this->expectExceptionMessage('minConfidence must be finite and within 0.0-1.0, got -0.1');

        new AuditExecutionConfiguration(
            maxIterations: 3,
            minConfidence: -0.1,
            reviewerBatchSize: 5,
            toolsEnabled: true,
            maxToolIterations: 5,
        );
    }

    /**
     * @throws InvalidAuditExecutionConfigurationException
     */
    public function test_optional_arguments_fall_back_to_their_documented_defaults(): void
    {
        $auditExecutionConfiguration = new AuditExecutionConfiguration(
            maxIterations: 3,
            minConfidence: 0.6,
            reviewerBatchSize: 5,
            toolsEnabled: true,
            maxToolIterations: 5,
        );

        self::assertTrue($auditExecutionConfiguration->staticPreScanEnabled);
        self::assertFalse($auditExecutionConfiguration->staticPreScanLeanMode);
        self::assertFalse($auditExecutionConfiguration->reviewerToolsEnabled);
        self::assertSame(4, $auditExecutionConfiguration->reviewerMaxToolIterations);
        self::assertSame(1, $auditExecutionConfiguration->reviewerMaxConcurrent);
        self::assertSame(1, $auditExecutionConfiguration->attackerMaxConcurrent);
        self::assertSame('feature', $auditExecutionConfiguration->chunkingStrategy);
        self::assertFalse($auditExecutionConfiguration->poCSynthesisEnabled);
        self::assertSame('high', $auditExecutionConfiguration->poCSynthesisSeverityFloor);
        self::assertFalse($auditExecutionConfiguration->codeSlicingEnabled);
        self::assertSame(80, $auditExecutionConfiguration->codeSlicingMinLines);
        self::assertFalse($auditExecutionConfiguration->escalationEnabled);
        self::assertNull($auditExecutionConfiguration->escalationCheapModel);
        self::assertTrue($auditExecutionConfiguration->structuredCollection);
        self::assertTrue($auditExecutionConfiguration->reviewerStructuredCollection);
        self::assertTrue($auditExecutionConfiguration->stableSystemPrompt);
    }
}
