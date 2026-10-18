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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\InconclusiveAnalysisRecorderInterface;

/**
 * Test fake: an attacker that reaches its last tool round on every file it is
 * given and finds nothing, so each file ends `analyzed` on a partial look.
 */
final readonly class InconclusiveAttackerAgent implements AttackerAgentInterface
{
    #[Override]
    public function analyze(AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder): array
    {
        foreach ($attackerAnalysisRequest->files as $projectFile) {
            $coverageRecorder->recordCoverage(AgentRole::Attacker->value, $projectFile->relativePath(), 'analyzed');
            if ($coverageRecorder instanceof InconclusiveAnalysisRecorderInterface) {
                $coverageRecorder->recordInconclusiveAnalysis(AgentRole::Attacker->value, $projectFile->relativePath());
            }
        }

        return [];
    }
}
