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
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingAttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Pipeline\Fixture\RecordingProgressReporter;

/**
 * Drives the orchestrator end-to-end via real AttackerAgent + ReviewerAgent,
 * stubbing only the LLMClientInterface boundary (per testing.md: mock at
 * system boundaries only, never internal Application/Domain collaborators).
 */
final class AuditOrchestratorTest extends TestCase
{
    private string $tmpDir;

    public function test_it_skips_audit_when_no_mapping(): void
    {
        $attackerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $attackerLlm->expects(self::never())->method('complete');
        $reviewerLlm->expects(self::never())->method('complete');
        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);

        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_runs_attacker_and_reviewer_loop(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'Vuln v1')]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
    }

    public function test_it_stops_when_attacker_finds_nothing(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn($this->emptyResponse());
        $reviewerLlm->expects(self::never())->method('complete');

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
        self::assertSame(1, $auditContext->getMeta('audit.iterations'));
    }

    public function test_it_deduplicates_vulnerabilities_across_iterations(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(
            $this->attackerResponse([$this->vulnPayload(title: 'Vuln v1')]),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_it_breaks_early_when_iteration_yields_no_new_unique_findings(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(
            $this->attackerResponse([$this->vulnPayload(title: 'Vuln v1')]),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertSame(2, $auditContext->getMeta('audit.iterations'));
    }

    public function test_it_filters_low_confidence_findings(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(
            $this->attackerResponse([$this->vulnPayload(title: 'low', confidence: 0.3)]),
        );
        $reviewerLlm->expects(self::never())->method('complete');

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_stores_audit_metadata_in_context(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn($this->emptyResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertNotNull($auditContext->getMeta('audit.iterations'));
        self::assertNotNull($auditContext->getMeta('audit.total_findings'));
        self::assertNotNull($auditContext->getMeta('audit.validated'));
        self::assertNotNull($auditContext->getMeta('audit.risk_score'));
    }

    public function test_it_runs_exactly_max_iterations_when_new_findings_each_time(): void
    {
        $iterationCount = 0;

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm
            ->method('complete')
            ->willReturnCallback(function () use (&$iterationCount): LLMResponse {
                ++$iterationCount;

                if ($iterationCount > 10) {
                    throw new RuntimeException('orchestrator exceeded safety bound: '.$iterationCount.' attacker calls');
                }

                return $this->attackerResponse([$this->vulnPayload(
                    title: 'Vuln iter'.$iterationCount,
                    filePath: 'src/File'.$iterationCount.'.php',
                )]);
            });
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertSame(3, $auditContext->getMeta('audit.iterations'));
        self::assertSame(3, $iterationCount);
    }

    public function test_it_accepts_vulnerability_at_exact_confidence_threshold(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'threshold', confidence: 0.6)]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_it_rejects_vulnerability_just_below_confidence_threshold(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(
            $this->attackerResponse([$this->vulnPayload(title: 'below', confidence: 0.59)]),
        );
        $reviewerLlm->expects(self::never())->method('complete');

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_deduplicates_by_overlapping_line_ranges(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'SQL A', lineStart: 10, lineEnd: 20)]),
            $this->attackerResponse([$this->vulnPayload(title: 'SQL B', lineStart: 15, lineEnd: 25)]),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_it_stores_exact_metadata_values_after_orchestration(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'Vuln v1')]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertSame(2, $auditContext->getMeta('audit.iterations'));
        self::assertSame(1, $auditContext->getMeta('audit.total_findings'));
        self::assertSame(1, $auditContext->getMeta('audit.validated'));
        self::assertSame(7, $auditContext->getMeta('audit.risk_score'));
    }

    public function test_it_continues_processing_remaining_reviewed_findings_after_duplicate(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'dup', lineStart: 10, lineEnd: 15)]),
            $this->attackerResponse([
                $this->vulnPayload(title: 'dup', lineStart: 10, lineEnd: 15),
                $this->vulnPayload(title: 'new', lineStart: 20, lineEnd: 30),
            ]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        // Both unique vulnerabilities should be persisted (not just the first after encountering dup)
        self::assertCount(2, $auditContext->vulnerabilities());
    }

    public function test_lines_overlap_detects_touching_ranges(): void
    {
        // linesOverlap: $start1 <= $end2 && $start2 <= $end1
        // With <= changed to <: touching ranges (end1==start2) would NOT be treated as overlapping.
        // This test ensures end1==start2 IS treated as overlapping (i.e. duplicate).
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'SQL A', lineStart: 10, lineEnd: 20)]),
            // start2==20 == end1==20 → touching, should be treated as overlap (duplicate)
            $this->attackerResponse([$this->vulnPayload(title: 'SQL B', lineStart: 20, lineEnd: 30)]),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        // vuln2 overlaps with vuln1 (touching at line 20) → deduplicated → only 1 stored
        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_lines_overlap_does_not_deduplicate_non_overlapping_ranges(): void
    {
        // linesOverlap with &&→|| mutation: would treat ALL pairs as overlapping.
        // This test verifies truly separate ranges (1-5 and 10-15) are NOT deduplicated.
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'SQL A', lineStart: 1, lineEnd: 5)]),
            $this->attackerResponse([$this->vulnPayload(title: 'SQL B', lineStart: 10, lineEnd: 15)]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        // Non-overlapping ranges → both should be stored
        self::assertCount(2, $auditContext->vulnerabilities());
    }

    public function test_it_logs_iteration_complete_with_exact_new_unique_count(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'Vuln v1')]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['logger' => $logger]);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        $iterationCompleteLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => 'Iteration complete' === $entry[0],
        ));

        self::assertCount(1, $iterationCompleteLogs);
        self::assertSame(1, $iterationCompleteLogs[0][1]['new_unique']);
        self::assertSame(1, $iterationCompleteLogs[0][1]['iteration']);
        self::assertSame(1, $iterationCompleteLogs[0][1]['attacker_found']);
    }

    public function test_it_logs_audit_iteration_with_running_index(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn($this->emptyResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['logger' => $logger]);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        $iterationLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => str_starts_with($entry[0], 'Audit iteration '),
        ));

        self::assertSame('Audit iteration 1/3', $iterationLogs[0][0]);
    }

    public function test_it_logs_attacker_found_no_findings_when_filter_drops_all(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn($this->emptyResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['logger' => $logger]);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        $stoppedLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => 'Attacker found no new findings, stopping' === $entry[0],
        ));

        self::assertCount(1, $stoppedLogs);
    }

    public function test_it_records_only_validated_findings_in_reviewer_accepted_count(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([
                $this->vulnPayload(title: 'v1', lineStart: 10, lineEnd: 15),
                $this->vulnPayload(title: 'v2', lineStart: 30, lineEnd: 40),
            ]),
            $this->emptyResponse(),
        );
        // Reviewer batchSize=1 → one LLM call per vuln. Accept the first, reject the second.
        $reviewerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->reviewerAcceptResponse(),
            $this->reviewerRejectResponse(),
        );

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['logger' => $logger]);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        $iterationCompleteLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => 'Iteration complete' === $entry[0],
        ));

        self::assertCount(1, $iterationCompleteLogs);
        self::assertSame(1, $iterationCompleteLogs[0][1]['reviewer_accepted']);
    }

    public function test_it_logs_starting_attacker_vs_reviewer_loop_with_max_iterations(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn($this->emptyResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['logger' => $logger]);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        $startingLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => 'Starting attacker vs reviewer loop' === $entry[0],
        ));

        self::assertCount(1, $startingLogs);
        self::assertSame(['max_iterations' => 3], $startingLogs[0][1]);
    }

    public function test_lines_overlap_detects_touching_ranges_on_left_boundary(): void
    {
        // Covers $start1 <= $end2 boundary (mutant: <= → <).
        // existing vuln1 (10-20) persisted first; then vuln2 (5-10) — touching at start1==end2==10.
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'SQL A', lineStart: 10, lineEnd: 20)]),
            $this->attackerResponse([$this->vulnPayload(title: 'SQL B', lineStart: 5, lineEnd: 10)]),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm);
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        // start1==end2==10 → touching → overlap → dup → only 1 stored
        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_it_logs_warning_when_no_mapping_available(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('No mapping available, skipping audit');
        $logger->expects(self::never())->method('info');

        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['logger' => $logger]);
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditOrchestrator->orchestrate($auditContext);
    }

    public function test_it_respects_custom_max_iterations(): void
    {
        $iterationCount = 0;

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm
            ->method('complete')
            ->willReturnCallback(function () use (&$iterationCount): LLMResponse {
                ++$iterationCount;

                if ($iterationCount > 20) {
                    throw new RuntimeException('orchestrator exceeded safety bound: '.$iterationCount.' attacker calls');
                }

                return $this->attackerResponse([$this->vulnPayload(
                    title: 'Vuln iter'.$iterationCount,
                    filePath: 'src/File'.$iterationCount.'.php',
                )]);
            });
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator(
            $attackerLlm,
            $reviewerLlm,
            ['maxIterations' => 5],
        );
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertSame(5, $auditContext->getMeta('audit.iterations'));
    }

    public function test_it_respects_custom_min_confidence(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(
            $this->attackerResponse([$this->vulnPayload(title: 'borderline', confidence: 0.65)]),
        );
        $reviewerLlm->expects(self::never())->method('complete');

        $auditOrchestrator = $this->makeOrchestrator(
            $attackerLlm,
            $reviewerLlm,
            ['minConfidence' => 0.7],
        );
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_accepts_vulnerability_at_exact_custom_confidence_threshold(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'exact', confidence: 0.7)]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());

        $auditOrchestrator = $this->makeOrchestrator(
            $attackerLlm,
            $reviewerLlm,
            ['minConfidence' => 0.7],
        );
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_it_passes_previously_validated_findings_to_next_iteration(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'First', 0.9),
            new CodeLocation('src/A.php', 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );

        // Returns the same finding every iteration; iteration 1 persists it (0 previous),
        // iteration 2 sees it as previous (1) and re-finds a duplicate → loop stops.
        $recordingAttackerAgent = new RecordingAttackerAgent([$vulnerability]);

        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($reviewerLlm, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(),
        );

        $auditOrchestrator = new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings());
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertSame([0, 1], $recordingAttackerAgent->previousFindingsCountPerCall);
    }

    public function test_it_passes_only_reviewer_rejected_findings_to_next_iteration(): void
    {
        // The attacker returns both findings every iteration. The reviewer accepts
        // 'KeepMe' (src/Accepted.php) and rejects 'DropMe' (src/Rejected.php).
        // Iteration 2 must receive ONLY the rejected finding as rejected context:
        // - dropping the array_filter would feed back both (count 2);
        // - flipping !isReviewerValidated() would feed back the ACCEPTED finding
        //   instead, so the identity assertion below pins the correct one.
        // Both findings dedupe in iteration 2, so the loop stops.
        $recordingAttackerAgent = new RecordingAttackerAgent([
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'KeepMe', 0.9),
                new CodeLocation('src/Accepted.php', 1, 2),
                new VulnerabilityNarrative('d', 'a', 'p', 'r'),
                'c',
            ),
            Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'DropMe', 0.9),
                new CodeLocation('src/Rejected.php', 1, 2),
                new VulnerabilityNarrative('d', 'a', 'p', 'r'),
                'c',
            ),
        ]);

        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm->method('complete')->willReturnCallback(
            fn (string $system, string $user): LLMResponse => str_contains($user, 'KeepMe')
                ? $this->reviewerAcceptResponse()
                : $this->reviewerRejectResponse(),
        );
        $reviewerAgent = new ReviewerAgent(
            new ReviewerAgentCollaborators($reviewerLlm, new ReviewerPromptBuilder(), new NullLogger()),
            new ReviewerModeConfiguration(),
        );

        $auditOrchestrator = new AuditOrchestrator($recordingAttackerAgent, $reviewerAgent, new NullLogger(), new AuditLoopSettings());
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        self::assertSame([0, 1], $recordingAttackerAgent->rejectedFindingsCountPerCall);
        self::assertSame([0, 1], $recordingAttackerAgent->previousFindingsCountPerCall);
        self::assertCount(1, $recordingAttackerAgent->lastRejectedFindings);
        self::assertSame('src/Rejected.php', $recordingAttackerAgent->lastRejectedFindings[0]->filePath());
    }

    public function test_it_logs_starting_loop_with_custom_max_iterations(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$msg, $ctx];
            },
        );

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn($this->emptyResponse());

        $auditOrchestrator = $this->makeOrchestrator(
            $attackerLlm,
            $reviewerLlm,
            ['logger' => $logger, 'maxIterations' => 7],
        );
        $auditContext = $this->makeContextWithMapping();

        $auditOrchestrator->orchestrate($auditContext);

        $startingLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => 'Starting attacker vs reviewer loop' === $entry[0],
        ));

        self::assertSame(['max_iterations' => 7], $startingLogs[0][1]);
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/orchestrator_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    public function test_it_reports_each_iteration_start_with_iteration_counts(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'Vuln v1')]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());
        $recordingProgressReporter = new RecordingProgressReporter();
        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['recordingProgressReporter' => $recordingProgressReporter]);

        $auditOrchestrator->orchestrate($this->makeContextWithMapping());

        self::assertSame(
            [
                ['audit.iteration.started', ['iteration' => 1, 'max_iterations' => 3]],
                ['audit.iteration.started', ['iteration' => 2, 'max_iterations' => 3]],
            ],
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'audit.iteration.started' === $event[0],
            )),
        );
    }

    public function test_it_reports_review_start_with_finding_count(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([$this->vulnPayload(title: 'Vuln v1')]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturn($this->reviewerAcceptResponse());
        $recordingProgressReporter = new RecordingProgressReporter();
        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['recordingProgressReporter' => $recordingProgressReporter]);

        $auditOrchestrator->orchestrate($this->makeContextWithMapping());

        self::assertSame(
            [
                ['review.started', ['findings' => 1]],
            ],
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'review.started' === $event[0],
            )),
        );
    }

    public function test_it_reports_audit_started_with_file_and_mapping_counts(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn($this->emptyResponse());
        $recordingProgressReporter = new RecordingProgressReporter();
        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['recordingProgressReporter' => $recordingProgressReporter]);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/Controller/A.php', '/a', '<?php'),
            ProjectFile::create('src/Controller/B.php', '/b', '<?php'),
            ProjectFile::create('src/Entity/E.php', '/e', '<?php'),
            ProjectFile::create('src/Form/F.php', '/f', '<?php'),
        ]);
        $auditContext->setMapping(SymfonyMapping::of(
            ProjectFileInventory::fromGroups([
                'controllers' => [
                    ProjectFile::create('src/Controller/A.php', '/a', '<?php'),
                    ProjectFile::create('src/Controller/B.php', '/b', '<?php'),
                ],
                'voters' => [ProjectFile::create('src/Security/V.php', '/v', '<?php')],
                'forms' => [
                    ProjectFile::create('src/Form/F1.php', '/f1', '<?php'),
                    ProjectFile::create('src/Form/F2.php', '/f2', '<?php'),
                    ProjectFile::create('src/Form/F3.php', '/f3', '<?php'),
                ],
            ]),
            new AccessControlMap(),
        ));

        $auditOrchestrator->orchestrate($auditContext);

        self::assertSame(
            [['audit.started', ['files' => 4, 'controllers' => 2, 'voters' => 1, 'forms' => 3]]],
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'audit.started' === $event[0],
            )),
        );
    }

    public function test_it_reports_review_completed_with_accepted_and_rejected_counts(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->attackerResponse([
                $this->vulnPayload(title: 'v1', lineStart: 10, lineEnd: 15),
                $this->vulnPayload(title: 'v2', lineStart: 30, lineEnd: 40),
            ]),
            $this->emptyResponse(),
        );
        $reviewerLlm->method('complete')->willReturnOnConsecutiveCalls(
            $this->reviewerAcceptResponse(),
            $this->reviewerRejectResponse(),
        );
        $recordingProgressReporter = new RecordingProgressReporter();
        $auditOrchestrator = $this->makeOrchestrator($attackerLlm, $reviewerLlm, ['recordingProgressReporter' => $recordingProgressReporter]);

        $auditOrchestrator->orchestrate($this->makeContextWithMapping());

        self::assertSame(
            [['review.completed', ['accepted' => 1, 'rejected' => 1]]],
            array_values(array_filter(
                $recordingProgressReporter->events,
                static fn (array $event): bool => 'review.completed' === $event[0],
            )),
        );
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
        return new AuditOrchestrator(
            attackerAgent: new AttackerAgent(
                new AttackerLlmCollaborators(
                    $attackerLlm,
                    new AttackerPromptBuilder(),
                    new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                ),
                new AttackerScanCollaborators(
                    new NullAttackerCache(),
                ),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            reviewerAgent: new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLlm,
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                ),
                new ReviewerModeConfiguration(),
            ),
            logger: $overrides['logger'] ?? new NullLogger(),
            loopSettings: new AuditLoopSettings(
                $overrides['maxIterations'] ?? AuditOrchestrator::DEFAULT_MAX_ITERATIONS,
                $overrides['minConfidence'] ?? AuditOrchestrator::DEFAULT_MIN_CONFIDENCE,
            ),
            progressReporter: $overrides['recordingProgressReporter'] ?? null,
        );
    }

    private function makeContextWithMapping(): AuditContext
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/Controller/Foo.php', '/app/src/Controller/Foo.php', '<?php'),
        ]);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        return $auditContext;
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
        return [
            'type' => 'sql_injection',
            'severity' => 'high',
            'title' => $title,
            'description' => 'desc',
            'file_path' => $filePath,
            'line_start' => $lineStart,
            'line_end' => $lineEnd,
            'vulnerable_code' => '$db->query($input)',
            'attack_vector' => 'SQL injection',
            'proof' => "' OR 1=1",
            'remediation' => 'Use prepared statements',
            'confidence' => $confidence,
        ];
    }

    /** @param list<array<string, mixed>> $vulns */
    private function attackerResponse(array $vulns): LLMResponse
    {
        return LLMResponse::of((string) json_encode($vulns), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }

    private function emptyResponse(): LLMResponse
    {
        return LLMResponse::of('[]', 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }

    private function reviewerAcceptResponse(): LLMResponse
    {
        return LLMResponse::of((string) json_encode(['accepted' => true]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }

    private function reviewerRejectResponse(): LLMResponse
    {
        return LLMResponse::of((string) json_encode(['accepted' => false]), 'test', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }
}
