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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\ToolsScope;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * The loop-tuning knobs of the attacker/reviewer orchestration.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AuditLoopSettings
{
    public function __construct(
        public int $maxIterations = AuditOrchestrator::DEFAULT_MAX_ITERATIONS,
        public float $minConfidence = AuditOrchestrator::DEFAULT_MIN_CONFIDENCE,
        public ToolsScope $toolsScope = ToolsScope::Audited,
    ) {}

    /**
     * @return ?list<ProjectFile> the files the investigation tools may open when they are not the files being audited; null keeps them to those
     */
    public function toolFiles(AuditContext $auditContext): ?array
    {
        return ToolsScope::Scanned === $this->toolsScope ? $auditContext->mappingFiles() : null;
    }
}
