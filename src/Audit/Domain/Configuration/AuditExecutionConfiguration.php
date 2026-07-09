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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditExecutionConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;

final readonly class AuditExecutionConfiguration
{
    /**
     * @param list<string> $excludedTypes vulnerability-type values dropped from the report and exit code
     * @param list<string> $includedTypes when non-empty, the only vulnerability-type values kept
     *
     * @throws InvalidAuditExecutionConfigurationException
     */
    public function __construct(
        public int $maxIterations,
        public float $minConfidence,
        public int $reviewerBatchSize,
        public bool $toolsEnabled,
        public int $maxToolIterations,
        public bool $staticPreScanEnabled = true,
        public bool $staticPreScanLeanMode = false,
        public bool $reviewerToolsEnabled = false,
        public int $reviewerMaxToolIterations = 4,
        public int $reviewerMaxConcurrent = 1,
        public int $attackerMaxConcurrent = 1,
        public string $chunkingStrategy = 'feature',
        public bool $poCSynthesisEnabled = false,
        public string $poCSynthesisSeverityFloor = 'high',
        public bool $codeSlicingEnabled = false,
        public int $codeSlicingMinLines = 80,
        public bool $escalationEnabled = false,
        public ?string $escalationCheapModel = null,
        public bool $structuredCollection = true,
        public bool $reviewerStructuredCollection = true,
        public bool $stableSystemPrompt = true,
        public ?string $baseline = null,
        public RiskLevel $failOn = RiskLevel::Critical,
        public array $excludedTypes = [],
        public array $includedTypes = [],
    ) {
        if (!is_finite($minConfidence) || $minConfidence < 0.0 || $minConfidence > 1.0) {
            throw InvalidAuditExecutionConfigurationException::forOutOfRangeMinConfidence($minConfidence);
        }
    }
}
