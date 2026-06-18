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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

/**
 * The two loop-tuning knobs of the attacker/reviewer orchestration.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AuditLoopSettings
{
    public function __construct(
        public int $maxIterations = AuditOrchestrator::DEFAULT_MAX_ITERATIONS,
        public float $minConfidence = AuditOrchestrator::DEFAULT_MIN_CONFIDENCE,
    ) {}
}
