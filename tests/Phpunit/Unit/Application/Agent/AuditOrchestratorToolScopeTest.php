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
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\InMemoryAdvisoryDatabase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\SymfonyToolRegistryFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\AuditOrchestratorHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingAttackerAgent;

final class AuditOrchestratorToolScopeTest extends TestCase
{
    private const string AUDITED_PATH = 'src/Controller/Foo.php';

    private const string UNCHANGED_PATH = 'src/Repository/FooRepository.php';

    private const string UNCHANGED_CONTENT = '<?php class FooRepository { /* unchanged-file-marker */ }';

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_the_attackers_tools_read_a_scanned_file_the_narrowed_run_does_not_audit(): void
    {
        $toolAnswers = [];
        $userMessages = [];
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('completeWithTools')->willReturnCallback(
            static function (string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry) use (&$toolAnswers, &$userMessages): LLMResponse {
                $toolAnswers[] = $toolRegistry->execute('read_file', ['relative_path' => self::UNCHANGED_PATH]);
                $userMessages[] = $userMessage;

                return AuditOrchestratorHarness::attackerResponse([]);
            },
        );

        $this->orchestrator($attackerLlm, self::createStub(LLMClientInterface::class), new ReviewerModeConfiguration())->orchestrate($this->narrowedContext());

        self::assertSame([self::UNCHANGED_CONTENT], $toolAnswers);
        self::assertStringNotContainsString('unchanged-file-marker', $userMessages[0]);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_the_reviewers_tools_read_a_scanned_file_the_narrowed_run_does_not_audit(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('completeWithTools')->willReturn(AuditOrchestratorHarness::attackerResponse([
            AuditOrchestratorHarness::vulnerabilityPayload(filePath: self::AUDITED_PATH),
        ]));
        $toolAnswers = [];
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('completeWithTools')->willReturnCallback(
            static function (string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry) use (&$toolAnswers): LLMResponse {
                $toolAnswers[] = $toolRegistry->execute('read_file', ['relative_path' => self::UNCHANGED_PATH]);

                return AuditOrchestratorHarness::reviewerAcceptResponse();
            },
        );

        $this->orchestrator($attackerLlm, $reviewerLlm, new ReviewerModeConfiguration(toolsEnabled: true, useStructuredCollection: false))->orchestrate($this->narrowedContext());

        self::assertSame([self::UNCHANGED_CONTENT], $toolAnswers);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws LLMProviderException
     */
    public function test_the_tools_of_the_review_that_follows_an_attacker_abort_read_a_scanned_file_the_narrowed_run_does_not_audit(): void
    {
        $toolAnswers = [];
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('completeWithTools')->willReturnCallback(
            static function (string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry) use (&$toolAnswers): LLMResponse {
                $toolAnswers[] = $toolRegistry->execute('read_file', ['relative_path' => self::UNCHANGED_PATH]);

                return AuditOrchestratorHarness::reviewerAcceptResponse();
            },
        );
        $recordingAttackerAgent = new RecordingAttackerAgent([$this->finding()], BudgetExceededException::forTokens(500, 100));

        $aborted = false;
        try {
            $this->orchestratorWith($recordingAttackerAgent, $reviewerLlm, new ReviewerModeConfiguration(toolsEnabled: true, useStructuredCollection: false))->orchestrate($this->narrowedContext());
        } catch (BudgetExceededException) {
            $aborted = true;
        }

        self::assertTrue($aborted);
        self::assertSame([self::UNCHANGED_CONTENT], $toolAnswers);
    }

    private function orchestrator(LLMClientInterface $attackerLlm, LLMClientInterface $reviewerLlm, ReviewerModeConfiguration $reviewerModeConfiguration): AuditOrchestrator
    {
        return $this->orchestratorWith(
            new AttackerAgent(
                new AttackerLlmCollaborators($attackerLlm, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator()), new NullCodeSlicer()),
                new AttackerScanCollaborators(new NullAttackerCache(), new NullStaticPreScanner(), new NullProgressReporter(), null, $this->toolRegistryFactory()),
                new AttackerAnalysisSettings(toolsEnabled: true, useStructuredCollection: false),
                new NullLogger(),
            ),
            $reviewerLlm,
            $reviewerModeConfiguration,
        );
    }

    private function orchestratorWith(AttackerAgentInterface $attackerAgent, LLMClientInterface $llmClient, ReviewerModeConfiguration $reviewerModeConfiguration): AuditOrchestrator
    {
        return new AuditOrchestrator(
            $attackerAgent,
            new ReviewerAgent(
                new ReviewerAgentCollaborators($llmClient, new ReviewerPromptBuilder(), new NullLogger()),
                $reviewerModeConfiguration,
                $this->toolRegistryFactory(),
            ),
            new NullLogger(),
            new AuditLoopSettings(maxIterations: 1),
            new NullProgressReporter(),
        );
    }

    private function toolRegistryFactory(): SymfonyToolRegistryFactory
    {
        return new SymfonyToolRegistryFactory(new NullLogger(), new InMemoryAdvisoryDatabase());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private function narrowedContext(): AuditContext
    {
        $projectFile = ProjectFile::create(self::AUDITED_PATH, '/app/'.self::AUDITED_PATH, '<?php class Foo {}');
        $unchanged = ProjectFile::create(self::UNCHANGED_PATH, '/app/'.self::UNCHANGED_PATH, self::UNCHANGED_CONTENT);

        $auditContext = AuditContext::forProject(__DIR__);
        $auditContext->setProjectFiles([$projectFile]);
        $auditContext->setMappingFiles([$projectFile, $unchanged]);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        return $auditContext;
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function finding(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Finding', 0.9),
            new CodeLocation(self::AUDITED_PATH, 10, 15),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
