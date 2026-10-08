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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
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
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReturningAttackerAgent;

final class AuditOrchestratorSeverityPrecedenceTest extends TestCase
{
    private string $tmpDir;

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[DataProvider('severityOrders')]
    public function test_it_keeps_the_highest_severity_when_the_attacker_reports_one_location_twice(VulnerabilitySeverity $first, VulnerabilitySeverity $second, VulnerabilitySeverity $expected): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([
                [...AuditOrchestratorHarness::vulnerabilityPayload(title: 'first'), 'severity' => $first->value],
                [...AuditOrchestratorHarness::vulnerabilityPayload(title: 'second'), 'severity' => $second->value],
            ]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        $validated = array_values($auditContext->validatedVulnerabilities());
        self::assertCount(1, $validated);
        self::assertSame($expected, $validated[0]->severity());
    }

    /**
     * @return iterable<string, array{VulnerabilitySeverity, VulnerabilitySeverity, VulnerabilitySeverity}>
     */
    public static function severityOrders(): iterable
    {
        yield 'critical reported before high' => [VulnerabilitySeverity::CRITICAL, VulnerabilitySeverity::HIGH, VulnerabilitySeverity::CRITICAL];
        yield 'high reported before critical' => [VulnerabilitySeverity::HIGH, VulnerabilitySeverity::CRITICAL, VulnerabilitySeverity::CRITICAL];
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[DataProvider('severityCorrections')]
    public function test_a_later_iteration_never_lowers_the_severity_of_an_already_validated_finding(VulnerabilitySeverity $firstVerdict, VulnerabilitySeverity $laterVerdict, VulnerabilitySeverity $expected): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload()]),
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload()]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->reviewerAcceptWithSeverityResponse($firstVerdict),
            $this->reviewerAcceptWithSeverityResponse($laterVerdict),
        );

        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        $validated = array_values($auditContext->validatedVulnerabilities());
        self::assertCount(1, $validated);
        self::assertSame($expected, $validated[0]->severity());
    }

    /**
     * @return iterable<string, array{VulnerabilitySeverity, VulnerabilitySeverity, VulnerabilitySeverity}>
     */
    public static function severityCorrections(): iterable
    {
        yield 'critical then downgraded to medium' => [VulnerabilitySeverity::CRITICAL, VulnerabilitySeverity::MEDIUM, VulnerabilitySeverity::CRITICAL];
        yield 'medium then raised to critical' => [VulnerabilitySeverity::MEDIUM, VulnerabilitySeverity::CRITICAL, VulnerabilitySeverity::CRITICAL];
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[DataProvider('overlappingSeverityOrders')]
    public function test_overlapping_findings_collapse_to_the_one_with_the_highest_severity(VulnerabilitySeverity $earlier, VulnerabilitySeverity $later, VulnerabilitySeverity $expectedSeverity, int $expectedLineStart): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([[...AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 10, lineEnd: 15), 'severity' => $earlier->value]]),
            AuditOrchestratorHarness::attackerResponse([[...AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 12, lineEnd: 18), 'severity' => $later->value]]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        $kept = array_values($auditContext->vulnerabilities());
        self::assertCount(1, $kept);
        self::assertSame($expectedSeverity, $kept[0]->severity());
        self::assertSame($expectedLineStart, $kept[0]->lineStart());
    }

    /**
     * @return iterable<string, array{VulnerabilitySeverity, VulnerabilitySeverity, VulnerabilitySeverity, int}>
     */
    public static function overlappingSeverityOrders(): iterable
    {
        yield 'a later critical replaces an earlier high' => [VulnerabilitySeverity::HIGH, VulnerabilitySeverity::CRITICAL, VulnerabilitySeverity::CRITICAL, 12];
        yield 'a later high does not replace an earlier critical' => [VulnerabilitySeverity::CRITICAL, VulnerabilitySeverity::HIGH, VulnerabilitySeverity::CRITICAL, 10];
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_rejected_finding_never_displaces_a_validated_one_at_an_overlapping_range(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([[...AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 10, lineEnd: 15), 'severity' => 'high']]),
            AuditOrchestratorHarness::attackerResponse([[...AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 12, lineEnd: 18), 'severity' => 'critical']]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::reviewerAcceptResponse(),
            LLMResponse::of((string) json_encode(['accepted' => false]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        $kept = array_values($auditContext->vulnerabilities());
        self::assertCount(1, $kept);
        self::assertSame(VulnerabilitySeverity::HIGH, $kept[0]->severity());
        self::assertTrue($kept[0]->isReviewerValidated());
    }

    /**
     * @param list<array{VulnerabilitySeverity, int, int}> $reportedFirst  severity, line start and line end of each finding the first iteration reports
     * @param array{VulnerabilitySeverity, int, int}       $reportedLater  the finding the second iteration reports
     * @param list<int>                                    $expectedStarts the line starts of the findings the report keeps
     *
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[DataProvider('collapsingIterations')]
    public function test_a_finding_overlapping_several_validated_ones_replaces_them_only_when_it_outranks_each(array $reportedFirst, array $reportedLater, array $expectedStarts): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse(array_map($this->payloadAt(...), $reportedFirst)),
            AuditOrchestratorHarness::attackerResponse([$this->payloadAt($reportedLater)]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        $starts = array_map(static fn (Vulnerability $vulnerability): int => $vulnerability->lineStart(), array_values($auditContext->vulnerabilities()));
        sort($starts);
        self::assertSame($expectedStarts, $starts);
    }

    /**
     * @return iterable<string, array{list<array{VulnerabilitySeverity, int, int}>, array{VulnerabilitySeverity, int, int}, list<int>}>
     */
    public static function collapsingIterations(): iterable
    {
        $apart = [[VulnerabilitySeverity::MEDIUM, 10, 12], [VulnerabilitySeverity::HIGH, 20, 22], [VulnerabilitySeverity::HIGH, 40, 45]];

        yield 'outranks every overlapped finding and leaves the others alone' => [$apart, [VulnerabilitySeverity::CRITICAL, 11, 21], [11, 40]];
        yield 'outranks only one of the overlapped findings' => [$apart, [VulnerabilitySeverity::HIGH, 11, 21], [10, 20, 40]];
        yield 'is outranked by every overlapped finding' => [$apart, [VulnerabilitySeverity::LOW, 11, 21], [10, 20, 40]];
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
    public function test_it_reviews_a_finding_the_attacker_returned_without_recording_it(): void
    {
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());
        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        $this->orchestratorWith(new ReturningAttackerAgent([$this->finding('returned')]), $reviewerLlm)->orchestrate($auditContext);

        self::assertSame(['returned'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), array_values($auditContext->validatedVulnerabilities())));
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
    public function test_a_recorded_copy_of_equal_rank_does_not_displace_the_finding_the_attacker_returned(): void
    {
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());
        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        $this->orchestratorWith(new ReturningAttackerAgent([$this->finding('returned')], [$this->finding('recorded')]), $reviewerLlm)->orchestrate($auditContext);

        self::assertSame(['returned'], array_map(static fn (Vulnerability $vulnerability): string => $vulnerability->title(), array_values($auditContext->validatedVulnerabilities())));
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_validated_finding_keeps_the_rejected_verdict_it_overlaps(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 10, lineEnd: 15)]),
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 12, lineEnd: 18)]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturnOnConsecutiveCalls(
            LLMResponse::of((string) json_encode(['accepted' => false]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
            AuditOrchestratorHarness::reviewerAcceptResponse(),
        );

        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        self::assertCount(2, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_overlapping_findings_of_another_type_or_file_are_both_kept(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([
                AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 10, lineEnd: 15),
                [...AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 10, lineEnd: 15), 'type' => 'ssrf'],
                AuditOrchestratorHarness::vulnerabilityPayload(lineStart: 10, lineEnd: 15, filePath: 'src/Controller/BarController.php'),
            ]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn(AuditOrchestratorHarness::reviewerAcceptResponse());

        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        self::assertCount(3, $auditContext->validatedVulnerabilities());
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[DataProvider('laterVerdicts')]
    public function test_a_later_verdict_replaces_a_validated_one_only_when_it_raises_the_severity_or_reclassifies_the_type(string $laterVerdict, VulnerabilitySeverity $vulnerabilitySeverity, VulnerabilityType $vulnerabilityType): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload()]),
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload()]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::reviewerAcceptResponse(),
            LLMResponse::of($laterVerdict, 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        $validated = array_values($auditContext->validatedVulnerabilities());
        self::assertCount(1, $validated);
        self::assertSame($vulnerabilitySeverity, $validated[0]->severity());
        self::assertSame($vulnerabilityType, $validated[0]->type());
    }

    /**
     * @return iterable<string, array{string, VulnerabilitySeverity, VulnerabilityType}>
     */
    public static function laterVerdicts(): iterable
    {
        yield 'the same severity under another type reclassifies' => ['{"accepted": true, "corrected_type": "ssrf"}', VulnerabilitySeverity::HIGH, VulnerabilityType::SSRF];
        yield 'a lower severity under another type does not replace' => ['{"accepted": true, "corrected_type": "ssrf", "adjusted_severity": "medium"}', VulnerabilitySeverity::HIGH, VulnerabilityType::SQL_INJECTION];
        yield 'a higher severity under another type replaces' => ['{"accepted": true, "corrected_type": "ssrf", "adjusted_severity": "critical"}', VulnerabilitySeverity::CRITICAL, VulnerabilityType::SSRF];
        yield 'the same severity and type is a duplicate' => ['{"accepted": true, "adjusted_severity": "high"}', VulnerabilitySeverity::HIGH, VulnerabilityType::SQL_INJECTION];
    }

    /**
     * @param array<string, mixed> $laterReport
     *
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[DataProvider('reReports')]
    public function test_a_re_report_asks_for_another_attacker_pass_only_when_it_adds_more_than_confidence(string $firstVerdict, array $laterReport, string $laterVerdict, int $expectedIterations): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            AuditOrchestratorHarness::attackerResponse([AuditOrchestratorHarness::vulnerabilityPayload(confidence: 0.8)]),
            AuditOrchestratorHarness::attackerResponse([$laterReport]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturnOnConsecutiveCalls(
            LLMResponse::of($firstVerdict, 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
            LLMResponse::of($laterVerdict, 'test', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $auditContext = AuditOrchestratorHarness::contextWithMapping($this->tmpDir);

        AuditOrchestratorHarness::orchestrator($attackerLlm, $reviewerLlm)->orchestrate($auditContext);

        self::assertSame($expectedIterations, $auditContext->getMeta('audit.iterations'));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>, string, int}>
     */
    public static function reReports(): iterable
    {
        $accept = '{"accepted": true}';
        $sameLocation = AuditOrchestratorHarness::vulnerabilityPayload(confidence: 0.85);
        $oneLineLower = AuditOrchestratorHarness::vulnerabilityPayload(confidence: 0.85, lineStart: 11, lineEnd: 16);

        yield 'the same finding with a higher confidence' => [$accept, $sameLocation, $accept, 2];
        yield 'the same weakness one line lower with a higher confidence' => [$accept, $oneLineLower, $accept, 2];
        yield 'the same finding with its severity raised by the reviewer' => [$accept, $sameLocation, '{"accepted": true, "adjusted_severity": "critical"}', 3];
        yield 'the same finding reclassified by the reviewer' => [$accept, $sameLocation, '{"accepted": true, "corrected_type": "ssrf"}', 3];
        yield 'the same weakness one line lower with a higher severity' => [$accept, [...$oneLineLower, 'severity' => 'critical'], $accept, 3];
        yield 'a validated finding at the place of a rejected one' => ['{"accepted": false}', $sameLocation, $accept, 3];
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/orchestrator_severity_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    private function orchestratorWith(AttackerAgentInterface $attackerAgent, LLMClientInterface $llmClient): AuditOrchestrator
    {
        return new AuditOrchestrator(
            $attackerAgent,
            new ReviewerAgent(
                new ReviewerAgentCollaborators($llmClient, new ReviewerPromptBuilder(), new NullLogger()),
                new ReviewerModeConfiguration(),
            ),
            new NullLogger(),
            new AuditLoopSettings(),
            new NullProgressReporter(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function finding(string $title): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, $title, 0.9),
            new CodeLocation('src/Controller/FooController.php', 10, 15),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }

    /**
     * @param array{VulnerabilitySeverity, int, int} $finding severity, line start and line end
     *
     * @return array<string, mixed>
     */
    private function payloadAt(array $finding): array
    {
        return [...AuditOrchestratorHarness::vulnerabilityPayload(lineStart: $finding[1], lineEnd: $finding[2]), 'severity' => $finding[0]->value];
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function reviewerAcceptWithSeverityResponse(VulnerabilitySeverity $vulnerabilitySeverity): LLMResponse
    {
        return LLMResponse::of((string) json_encode(['accepted' => true, 'adjusted_severity' => $vulnerabilitySeverity->value]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function emptyResponse(): LLMResponse
    {
        return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }
}
