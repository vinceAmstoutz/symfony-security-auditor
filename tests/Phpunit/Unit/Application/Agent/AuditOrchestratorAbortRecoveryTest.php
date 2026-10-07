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

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\AuditOrchestratorHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingAttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline\Fixture\RecordingProgressReporter;

final class AuditOrchestratorAbortRecoveryTest extends TestCase
{
    private string $tmpDir;

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     */
    public function test_it_persists_a_finding_validated_before_a_mid_review_budget_abort(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn($this->attackerResponse([
            $this->vulnPayload(title: 'v1', lineStart: 10, lineEnd: 15),
            $this->vulnPayload(title: 'v2', lineStart: 30, lineEnd: 40),
        ]));
        $callCount = 0;
        $reviewerLlm->method('complete')->willReturnCallback(function () use (&$callCount): LLMResponse {
            ++$callCount;
            if (2 === $callCount) {
                throw BudgetExceededException::forTokens(500, 100);
            }

            return $this->reviewerAcceptResponse();
        });

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $budgetExceeded = false;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The orchestrator must rethrow BudgetExceededException.');
        self::assertCount(1, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
        self::assertSame('v1', current($auditContext->validatedVulnerabilities())->title());
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     */
    public function test_it_reviews_and_persists_a_candidate_found_before_a_mid_attacker_budget_abort(): void
    {
        $files = [];
        for ($i = 1; $i <= 11; ++$i) {
            $files[] = ProjectFile::create(\sprintf('src/Service/Service%d.php', $i), \sprintf('/app/src/Service/Service%d.php', $i), '<?php');
        }

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $callCount = 0;
        $attackerLlm->method('complete')->willReturnCallback(function () use (&$callCount): LLMResponse {
            ++$callCount;
            if (2 === $callCount) {
                throw BudgetExceededException::forTokens(500, 100);
            }

            return $this->attackerResponse([$this->vulnPayload(title: 'v1', filePath: 'src/Service/Service1.php')]);
        });
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles($files);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        $budgetExceeded = false;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The orchestrator must rethrow BudgetExceededException.');
        self::assertCount(1, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
        self::assertSame('v1', current($auditContext->validatedVulnerabilities())->title());
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     */
    public function test_it_reports_review_start_before_reviewing_a_candidate_recovered_from_a_mid_attacker_budget_abort(): void
    {
        $files = [];
        for ($i = 1; $i <= 11; ++$i) {
            $files[] = ProjectFile::create(\sprintf('src/Service/Service%d.php', $i), \sprintf('/app/src/Service/Service%d.php', $i), '<?php');
        }

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $callCount = 0;
        $attackerLlm->method('complete')->willReturnCallback(function () use (&$callCount): LLMResponse {
            ++$callCount;
            if (2 === $callCount) {
                throw BudgetExceededException::forTokens(500, 100);
            }

            return $this->attackerResponse([$this->vulnPayload(title: 'v1', filePath: 'src/Service/Service1.php')]);
        });
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $recordingProgressReporter = new RecordingProgressReporter();
        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['recordingProgressReporter' => $recordingProgressReporter]);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles($files);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        $budgetExceeded = false;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The orchestrator must rethrow BudgetExceededException.');

        $reviewRelatedEvents = array_values(array_filter(
            $recordingProgressReporter->events,
            static fn (array $event): bool => \in_array($event[0], ['review.started', 'review.finding.reviewed'], true),
        ));

        self::assertSame('review.started', $reviewRelatedEvents[0][0]);
        self::assertSame(1, $reviewRelatedEvents[0][1]['findings']);
        self::assertSame('review.finding.reviewed', $reviewRelatedEvents[1][0]);
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     */
    public function test_it_swallows_a_second_abort_while_reviewing_a_recovered_candidate(): void
    {
        $files = [];
        for ($i = 1; $i <= 11; ++$i) {
            $files[] = ProjectFile::create(\sprintf('src/Service/Service%d.php', $i), \sprintf('/app/src/Service/Service%d.php', $i), '<?php');
        }

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $callCount = 0;
        $attackerLlm->method('complete')->willReturnCallback(function () use (&$callCount): LLMResponse {
            ++$callCount;
            if (2 === $callCount) {
                throw BudgetExceededException::forTokens(500, 100);
            }

            return $this->attackerResponse([$this->vulnPayload(title: 'v1', filePath: 'src/Service/Service1.php')]);
        });
        $reviewerLlm->method('complete')->willThrowException(BudgetExceededException::forTokens(500, 100));

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles($files);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        $budgetExceeded = false;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The orchestrator must rethrow the original attacker abort.');
        self::assertCount(0, $auditContext->vulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_recovers_a_finding_recorded_by_the_attacker_but_omitted_from_its_return_value(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Hidden', 0.9),
            new CodeLocation('src/A.php', 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );

        // Simulates a chunk whose conversation swallowed a generic (non-abort)
        // Throwable after a partial record_vulnerability success: the finding
        // reached the coverage recorder, but AttackerAgent::analyze() still
        // returns normally with it missing from the aggregate list.
        $recordingAttackerAgent = new RecordingAttackerAgent([], null, [$vulnerability]);

        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($reviewerLlm, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(),
        );

        $auditOrchestrator = new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings(), new NullProgressReporter());
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
        self::assertSame('Hidden', current($auditContext->validatedVulnerabilities())->title());
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/orchestrator_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     */
    public function test_it_persists_a_finding_validated_before_a_mid_review_provider_abort(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn($this->attackerResponse([
            $this->vulnPayload(title: 'v1', lineStart: 10, lineEnd: 15),
            $this->vulnPayload(title: 'v2', lineStart: 30, lineEnd: 40),
        ]));
        $callCount = 0;
        $reviewerLlm->method('complete')->willReturnCallback(function () use (&$callCount): LLMResponse {
            ++$callCount;
            if (2 === $callCount) {
                throw new LLMProviderException('provider failure');
            }

            return $this->reviewerAcceptResponse();
        });

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $providerFailed = false;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (LLMProviderException) {
            $providerFailed = true;
        }

        self::assertTrue($providerFailed, 'The orchestrator must rethrow LLMProviderException.');
        self::assertCount(1, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
        self::assertSame('v1', current($auditContext->validatedVulnerabilities())->title());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_reviews_a_candidate_found_before_a_mid_attacker_provider_abort(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Recovered', 0.9),
            new CodeLocation('src/A.php', 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
        $recordingAttackerAgent = new RecordingAttackerAgent([], new LLMProviderException('provider failure'), [$vulnerability]);

        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($reviewerLlm, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(),
        );

        $auditOrchestrator = new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings(), new NullProgressReporter());
        $auditContext = $this->makeContextWithMapping();

        $providerFailed = false;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (LLMProviderException) {
            $providerFailed = true;
        }

        self::assertTrue($providerFailed, 'The orchestrator must rethrow the attacker LLMProviderException.');
        self::assertCount(1, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
        self::assertSame('Recovered', current($auditContext->validatedVulnerabilities())->title());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     */
    public function test_it_does_not_report_review_start_when_no_candidate_survives_an_attacker_abort(): void
    {
        $recordingAttackerAgent = new RecordingAttackerAgent([], BudgetExceededException::forTokens(500, 100), []);

        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($reviewerLlm, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(),
        );

        $recordingProgressReporter = new RecordingProgressReporter();
        $auditOrchestrator = new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings(), $recordingProgressReporter);
        $auditContext = $this->makeContextWithMapping();

        $budgetExceeded = false;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The orchestrator must rethrow the attacker BudgetExceededException.');
        self::assertSame(
            [],
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'review.started' === $event[0],
            )),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     */
    public function test_it_reports_review_skipped_when_no_candidate_survives_an_attacker_abort(): void
    {
        $recordingAttackerAgent = new RecordingAttackerAgent([], BudgetExceededException::forTokens(500, 100), []);

        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($reviewerLlm, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(),
        );

        $recordingProgressReporter = new RecordingProgressReporter();
        $auditOrchestrator = new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings(), $recordingProgressReporter);
        $auditContext = $this->makeContextWithMapping();

        $budgetExceeded = false;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The orchestrator must rethrow the attacker BudgetExceededException.');
        self::assertContains(['review.skipped', ['reason' => 'nothing_recovered']], $recordingProgressReporter->events);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_rethrows_the_original_provider_abort_when_the_recovery_review_hits_a_budget_abort(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Recovered', 0.9),
            new CodeLocation('src/A.php', 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
        $recordingAttackerAgent = new RecordingAttackerAgent([], new LLMProviderException('provider failure'), [$vulnerability]);

        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willThrowException(BudgetExceededException::forTokens(500, 100));
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($reviewerLlm, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(),
        );

        $auditOrchestrator = new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings(), new NullProgressReporter());
        $auditContext = $this->makeContextWithMapping();

        $caught = null;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (BudgetExceededException|LLMProviderException $exception) {
            $caught = $exception;
        }

        self::assertInstanceOf(LLMProviderException::class, $caught);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_rethrows_the_original_budget_abort_when_the_recovery_review_hits_a_provider_abort(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Recovered', 0.9),
            new CodeLocation('src/A.php', 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
        $recordingAttackerAgent = new RecordingAttackerAgent([], BudgetExceededException::forTokens(500, 100), [$vulnerability]);

        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willThrowException(new LLMProviderException('provider failure'));
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($reviewerLlm, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(),
        );

        $auditOrchestrator = new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings(), new NullProgressReporter());
        $auditContext = $this->makeContextWithMapping();

        $caught = null;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (BudgetExceededException|LLMProviderException $exception) {
            $caught = $exception;
        }

        self::assertInstanceOf(BudgetExceededException::class, $caught);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws LLMProviderException
     */
    public function test_it_persists_recovered_findings_reviewed_before_a_second_budget_abort(): void
    {
        $recordingAttackerAgent = new RecordingAttackerAgent([], BudgetExceededException::forTokens(500, 100), [
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'FirstRecovered', 0.9),
                new CodeLocation('src/First.php', 1, 2),
                new VulnerabilityNarrative('d', 'a', 'p', 'r'),
                'c',
            ),
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'SecondRecovered', 0.9),
                new CodeLocation('src/Second.php', 1, 2),
                new VulnerabilityNarrative('d', 'a', 'p', 'r'),
                'c',
            ),
        ]);

        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $callCount = 0;
        $reviewerLlm->method('complete')->willReturnCallback(function () use (&$callCount): LLMResponse {
            ++$callCount;
            if (2 === $callCount) {
                throw BudgetExceededException::forTokens(500, 100);
            }

            return $this->reviewerAcceptResponse();
        });
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($reviewerLlm, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(),
        );

        $auditOrchestrator = new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings(), new NullProgressReporter());
        $auditContext = $this->makeContextWithMapping();

        $budgetExceeded = false;
        try {
            $auditOrchestrator->orchestrate($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The orchestrator must rethrow the original attacker BudgetExceededException.');
        self::assertCount(1, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
        self::assertSame('FirstRecovered', current($auditContext->validatedVulnerabilities())->title());
    }

    /**
     * @param array{
     *     logger?: LoggerInterface,
     *     maxIterations?: int,
     *     minConfidence?: float,
     *     recordingProgressReporter?: RecordingProgressReporter,
     * } $overrides
     */
    private function makeOrchestrator(
        LLMClientInterface $attackerLlm,
        LLMClientInterface $reviewerLlm,
        array $overrides = [],
    ): AuditOrchestrator {
        return AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm, $overrides);
    }

    /** @param list<string> $acceptedFingerprints
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private function makeContextWithMapping(array $acceptedFingerprints = []): AuditContext
    {
        return AuditOrchestratorHarness::contextWithMapping($this->tmpDir, $acceptedFingerprints);
    }

    /**
     * @return array<string, mixed>
     */
    private function vulnPayload(
        string $title = 'Vuln',
        float $confidence = 0.9,
        int $lineStart = 10,
        int $lineEnd = 15,
        string $filePath = 'src/Controller/FooController.php',
    ): array {
        return AuditOrchestratorHarness::vulnerabilityPayload($title, $confidence, $lineStart, $lineEnd, $filePath);
    }

    /** @param list<array<string, mixed>> $vulns
     *
     * @throws InvalidTokenUsageException
     */
    private function attackerResponse(array $vulns): LLMResponse
    {
        return AuditOrchestratorHarness::attackerResponse($vulns);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function reviewerAcceptResponse(): LLMResponse
    {
        return AuditOrchestratorHarness::reviewerAcceptResponse();
    }
}
