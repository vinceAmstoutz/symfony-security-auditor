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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageCriticInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageGap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;

/**
 * Test fake: a real CoverageCriticInterface implementation that names the
 * same gaps on every call, so a test drives the orchestrator's critic pass
 * without an LLM, and records how many findings were confirmed each time it
 * was asked.
 */
final class FixedCoverageCritic implements CoverageCriticInterface
{
    /** @var list<int> how many findings the reviewer had confirmed at each call */
    public array $validatedFindingsPerCall = [];

    /**
     * @param list<CoverageGap> $gaps
     */
    public function __construct(
        private readonly array $gaps,
    ) {}

    #[Override]
    public function gaps(SymfonyMapping $symfonyMapping, AuditContext $auditContext): array
    {
        $this->validatedFindingsPerCall[] = \count($auditContext->validatedVulnerabilities());

        return $this->gaps;
    }
}
