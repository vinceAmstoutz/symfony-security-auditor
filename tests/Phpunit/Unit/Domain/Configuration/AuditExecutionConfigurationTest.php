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

final class AuditExecutionConfigurationTest extends TestCase
{
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
