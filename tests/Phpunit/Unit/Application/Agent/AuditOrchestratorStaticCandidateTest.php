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

use Exception;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\AuditOrchestratorHarness;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\FailingLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingLLMClient;

/**
 * Drives the static candidates through the real AttackerAgent and
 * ReviewerAgent, stubbing only the LLMClientInterface boundary.
 */
final class AuditOrchestratorStaticCandidateTest extends TestCase
{
    private const string FILE = 'src/Controller/FooController.php';

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_attacker_finding_on_the_line_of_a_static_candidate_is_reviewed_in_its_place(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(AuditOrchestratorHarness::attackerResponse([
            AuditOrchestratorHarness::vulnerabilityPayload(title: 'Order id concatenated into native SQL', confidence: 0.75, lineStart: 10, lineEnd: 12),
        ]));
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm->expects(self::once())->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = $this->contextWith([$this->staticCandidate(10)]);
        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm, ['maxIterations' => 1])->orchestrate($auditContext);

        self::assertSame(['Order id concatenated into native SQL'], $this->validatedTitles($auditContext));
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_baseline_accepted_static_candidate_keeps_the_attacker_finding_on_its_lines_out_of_review(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(AuditOrchestratorHarness::attackerResponse([
            AuditOrchestratorHarness::vulnerabilityPayload(title: 'Order id concatenated into native SQL', lineStart: 9, lineEnd: 12),
        ]));
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm->expects(self::never())->method('complete');

        $staticCandidate = $this->staticCandidate(10);
        $auditContext = $this->contextWith([$staticCandidate], [$staticCandidate->fingerprint()]);
        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm, ['maxIterations' => 1])->orchestrate($auditContext);

        self::assertSame([], $auditContext->vulnerabilities());
        self::assertSame([$staticCandidate->fingerprint()], $auditContext->consumedBaselineFingerprints());
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_two_static_candidates_on_one_line_are_reviewed_once_as_the_more_confident(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(AuditOrchestratorHarness::attackerResponse([]));
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm->expects(self::once())->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = $this->contextWith([
            $this->staticCandidate(4, 'Static analysis: env credential assignment', confidence: 0.8, vulnerabilityType: VulnerabilityType::HARDCODED_SECRET),
            $this->staticCandidate(4, 'Hardcoded secret committed in source', confidence: 0.95, vulnerabilityType: VulnerabilityType::HARDCODED_SECRET),
        ]);
        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm, ['maxIterations' => 1])->orchestrate($auditContext);

        self::assertSame(['Hardcoded secret committed in source'], $this->validatedTitles($auditContext));
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_static_candidate_of_another_type_than_the_attacker_finding_on_its_line_is_still_reviewed(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(AuditOrchestratorHarness::attackerResponse([
            AuditOrchestratorHarness::vulnerabilityPayload(title: 'Order id concatenated into native SQL', lineStart: 10, lineEnd: 12),
        ]));
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm->expects(self::exactly(2))->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = $this->contextWith([$this->staticCandidate(10, 'Static analysis: unserialize call', vulnerabilityType: VulnerabilityType::INSECURE_DESERIALIZATION)]);
        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm, ['maxIterations' => 1])->orchestrate($auditContext);

        self::assertEqualsCanonicalizing(['Order id concatenated into native SQL', 'Static analysis: unserialize call'], $this->validatedTitles($auditContext));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws LLMProviderException
     */
    public function test_a_lead_below_the_confidence_floor_is_reviewed_when_the_attacker_aborts_as_in_a_complete_run(): void
    {
        $auditContext = $this->contextWith([$this->staticCandidate(10, 'Static analysis: role check only', VulnerabilitySeverity::LOW, 0.5)]);

        $budgetExceeded = false;
        try {
            AuditOrchestratorHarness::orchestrator(
                new FailingLLMClient(BudgetExceededException::forTokens(500, 100)),
                new RecordingLLMClient((string) json_encode(['accepted' => true])),
            )->orchestrate($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The orchestrator must rethrow BudgetExceededException.');
        self::assertSame(['Static analysis: role check only'], $this->validatedTitles($auditContext));
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_reviewed_static_candidate_alone_does_not_start_another_attacker_iteration(): void
    {
        $attackerLlm = $this->createMock(LLMClientInterface::class);
        $attackerLlm->expects(self::once())->method('complete')->willReturn(AuditOrchestratorHarness::attackerResponse([]));
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = $this->contextWith([$this->staticCandidate(10)]);
        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        self::assertSame(1, $auditContext->getMeta('audit.iterations'));
        self::assertSame(['Static analysis: native query concat'], $this->validatedTitles($auditContext));
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_attacker_finding_sharing_the_id_of_a_static_candidate_starts_another_attacker_iteration(): void
    {
        $attackerLlm = $this->createMock(LLMClientInterface::class);
        $attackerLlm->expects(self::exactly(2))->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload(title: 'Order id concatenated into native SQL', lineStart: 10, lineEnd: 12)]),
            AuditOrchestratorHarness::attackerResponse([]),
        );
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = $this->contextWith([$this->staticCandidate(10)]);
        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        self::assertSame(2, $auditContext->getMeta('audit.iterations'));
        self::assertSame(['Order id concatenated into native SQL'], $this->validatedTitles($auditContext));
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_attacker_finding_recovered_from_an_abort_is_reviewed_apart_from_the_static_candidates_of_its_file_when_it_shares_the_id_of_one(): void
    {
        $attackerCalls = 0;
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnCallback(static function () use (&$attackerCalls): LLMResponse {
            if (2 === ++$attackerCalls) {
                throw BudgetExceededException::forTokens(500, 100);
            }

            return AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload(title: 'Order id concatenated into native SQL', lineStart: 10, lineEnd: 12)]);
        });
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm->expects(self::exactly(2))->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = $this->contextWith([
            $this->staticCandidate(10),
            $this->staticCandidate(20, 'Static analysis: unserialize call', vulnerabilityType: VulnerabilityType::INSECURE_DESERIALIZATION),
        ]);
        $auditContext->setProjectFiles(array_map(
            static fn (int $index): ProjectFile => ProjectFile::create(\sprintf('src/Service/Service%d.php', $index), \sprintf('/app/src/Service/Service%d.php', $index), '<?php'),
            range(1, 11),
        ));

        $budgetExceeded = false;
        try {
            AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm, ['maxIterations' => 1])->orchestrate($auditContext);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'The orchestrator must rethrow BudgetExceededException.');
        self::assertEqualsCanonicalizing(['Order id concatenated into native SQL', 'Static analysis: unserialize call'], $this->validatedTitles($auditContext));
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_static_candidates_of_one_file_are_reviewed_in_one_call(): void
    {
        $first = $this->staticCandidate(10);
        $second = $this->staticCandidate(20, 'Static analysis: unserialize call', vulnerabilityType: VulnerabilityType::INSECURE_DESERIALIZATION);
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(AuditOrchestratorHarness::attackerResponse([]));
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm->expects(self::once())->method('complete')->willReturn(LLMResponse::of(
            (string) json_encode([['id' => $first->id(), 'accepted' => true], ['id' => $second->id(), 'accepted' => true]]),
            'test',
            'end_turn',
            TokenUsageSnapshot::of(0, 0),
        ));

        $auditContext = $this->contextWith([$first, $second]);
        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        self::assertEqualsCanonicalizing(['Static analysis: native query concat', 'Static analysis: unserialize call'], $this->validatedTitles($auditContext));
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('reviewAbortCases')]
    public function test_an_abort_while_reviewing_the_attacker_findings_marks_the_static_candidates_unreached(Exception $exception, string $status): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 40, lineEnd: 42)]));
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willThrowException($exception);

        $auditContext = $this->contextWith([$this->staticCandidate(10)]);
        $aborted = false;
        try {
            AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm, ['maxIterations' => 1])->orchestrate($auditContext);
        } catch (BudgetExceededException|LLMProviderException) {
            $aborted = true;
        }

        self::assertTrue($aborted, 'The orchestrator must rethrow the abort.');
        self::assertSame(
            [['stage' => 'reviewer', 'file' => self::FILE, 'status' => $status], ['stage' => 'reviewer', 'file' => self::FILE, 'status' => $status]],
            array_values(array_filter($auditContext->coverage(), static fn (array $entry): bool => 'reviewer' === $entry['stage'])),
        );
    }

    /** @return iterable<string, array{Exception, string}> */
    public static function reviewAbortCases(): iterable
    {
        yield 'budget exceeded' => [BudgetExceededException::forTokens(500, 100), 'aborted'];
        yield 'provider failure' => [new LLMProviderException('platform unreachable'), 'errored'];
    }

    /**
     * @param list<Vulnerability> $staticCandidates
     * @param list<string>        $acceptedFingerprints
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private function contextWith(array $staticCandidates, array $acceptedFingerprints = []): AuditContext
    {
        $auditContext = AuditOrchestratorHarness::contextWithMapping(sys_get_temp_dir(), $acceptedFingerprints);
        foreach ($staticCandidates as $staticCandidate) {
            $auditContext->addStaticCandidate($staticCandidate);
        }

        return $auditContext;
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function staticCandidate(int $line, string $title = 'Static analysis: native query concat', VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH, float $confidence = 0.8, VulnerabilityType $vulnerabilityType = VulnerabilityType::SQL_INJECTION): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, $vulnerabilitySeverity, $title, $confidence),
            new CodeLocation(self::FILE, $line, $line),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }

    /**
     * @return list<string>
     */
    private function validatedTitles(AuditContext $auditContext): array
    {
        return array_values(array_map(
            static fn (Vulnerability $vulnerability): string => $vulnerability->title(),
            $auditContext->validatedVulnerabilities(),
        ));
    }
}
