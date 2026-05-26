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

final readonly class AuditExecutionConfiguration
{
    public function __construct(
        public int $maxIterations,
        public float $minConfidence,
        public int $reviewerBatchSize,
        public bool $toolsEnabled,
        public int $maxToolIterations,
        public bool $staticPreScanEnabled = true,
        public bool $staticPreScanLeanMode = false,
    ) {}
}
