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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

final readonly class ReturningAttackerAgent implements AttackerAgentInterface
{
    /**
     * @param list<Vulnerability> $returnFindings   returned on every call, never recorded through the coverage recorder
     * @param list<Vulnerability> $recordedFindings recorded through the coverage recorder on every call, never returned
     */
    public function __construct(
        private array $returnFindings,
        private array $recordedFindings = [],
    ) {}

    #[Override]
    public function analyze(AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder): array
    {
        foreach ($this->recordedFindings as $recordedFinding) {
            $coverageRecorder->recordFoundVulnerability($recordedFinding);
        }

        return $this->returnFindings;
    }
}
