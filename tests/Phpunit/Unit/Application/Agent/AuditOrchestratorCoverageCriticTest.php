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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\CoverageGap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\AuditOrchestratorHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\FixedCoverageCritic;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingAttackerAgent;

final class AuditOrchestratorCoverageCriticTest extends TestCase
{
    private const string AUDITED_PATH = 'src/Controller/Foo.php';

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidTokenUsageException
     */
    public function test_a_finding_on_a_gap_the_critic_names_after_the_loop_is_reviewed_and_reported(): void
    {
        $auditContext = AuditOrchestratorHarness::contextWithMapping(sys_get_temp_dir());
        $coverageCritic = new FixedCoverageCritic([new CoverageGap($auditContext->projectFiles(), 'The bulk export skips the owner check.', 'broken_access_control')]);

        AuditOrchestratorHarness::orchestrator($this->attackerFindingOnlyOnTheGap(), $this->acceptingReviewer(), ['coverageCritic' => $coverageCritic])->orchestrate($auditContext);

        self::assertSame(['Bulk export without owner check'], $this->validatedTitles($auditContext));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidTokenUsageException
     */
    public function test_the_critic_is_asked_once_after_the_loop_with_the_findings_it_confirmed(): void
    {
        $coverageCritic = new FixedCoverageCritic([]);
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload(title: 'Loop finding', filePath: self::AUDITED_PATH)]),
            AuditOrchestratorHarness::attackerResponse([]),
        );

        AuditOrchestratorHarness::orchestrator($attackerLlm, $this->acceptingReviewer(), ['coverageCritic' => $coverageCritic])->orchestrate(AuditOrchestratorHarness::contextWithMapping(sys_get_temp_dir()));

        self::assertSame([1], $coverageCritic->validatedFindingsPerCall);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_the_attacker_analyzes_only_the_files_of_the_gap_while_its_tools_reach_every_audited_file(): void
    {
        $auditContext = AuditOrchestratorHarness::contextWithMapping(sys_get_temp_dir());
        $handler = ProjectFile::create('src/MessageHandler/FooHandler.php', '/app/src/MessageHandler/FooHandler.php', '<?php');
        $auditContext->setProjectFiles([...$auditContext->projectFiles(), $handler]);
        $recordingAttackerAgent = new RecordingAttackerAgent();
        $reviewerAgent = new ReviewerAgent(new ReviewerAgentCollaborators(self::createStub(LLMClientInterface::class), new ReviewerPromptBuilder(), new NullLogger()), new ReviewerModeConfiguration());
        $coverageCritic = new FixedCoverageCritic([new CoverageGap([$handler], 'The handler skips the owner check.', 'broken_access_control')]);

        (new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings(), new NullProgressReporter(), $coverageCritic))->orchestrate($auditContext);

        self::assertSame(
            [2, [$handler], $auditContext->projectFiles()],
            [$recordingAttackerAgent->callCount, $recordingAttackerAgent->lastFiles, $recordingAttackerAgent->lastToolFiles],
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidTokenUsageException
     */
    public function test_a_gap_whose_analysis_is_cut_short_leaves_the_audit_complete(): void
    {
        $auditContext = AuditOrchestratorHarness::contextWithMapping(sys_get_temp_dir());
        $coverageCritic = new FixedCoverageCritic([new CoverageGap($auditContext->projectFiles(), 'The bulk export skips the owner check.', 'broken_access_control')]);
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnCallback(
            static fn (string $systemPrompt, string $userMessage): LLMResponse => str_contains($userMessage, 'Coverage critic hypothesis')
                ? LLMResponse::of('', 'test', 'length', TokenUsageSnapshot::of(0, 0))
                : AuditOrchestratorHarness::attackerResponse([]),
        );

        AuditOrchestratorHarness::orchestrator($attackerLlm, $this->acceptingReviewer(), ['coverageCritic' => $coverageCritic])->orchestrate($auditContext);

        self::assertNotContains('errored', array_column($auditContext->coverage(), 'status'));
    }

    /**
     * @return list<string>
     */
    private function validatedTitles(AuditContext $auditContext): array
    {
        return array_values(array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), $auditContext->validatedVulnerabilities()));
    }

    private function attackerFindingOnlyOnTheGap(): LLMClientInterface
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnCallback(
            static fn (string $systemPrompt, string $userMessage): LLMResponse => AuditOrchestratorHarness::attackerResponse(
                str_contains($userMessage, 'Coverage critic hypothesis') ? [AuditOrchestratorHarness::vulnerabilityPayload(title: 'Bulk export without owner check', filePath: self::AUDITED_PATH)] : [],
            ),
        );

        return $attackerLlm;
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function acceptingReviewer(): LLMClientInterface
    {
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        return $reviewerLlm;
    }
}
