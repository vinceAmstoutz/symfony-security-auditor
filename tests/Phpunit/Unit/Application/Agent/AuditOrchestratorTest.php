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

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class AuditOrchestratorTest extends TestCase
{
    private AttackerAgentInterface&MockObject $attackerAgent;

    private ReviewerAgentInterface&MockObject $reviewerAgent;

    private AuditOrchestrator $auditOrchestrator;

    private string $tmpDir;

    public function test_it_skips_audit_when_no_mapping(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $this->attackerAgent->expects(self::never())->method('analyze');
        $this->reviewerAgent->expects(self::never())->method('review');

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_runs_attacker_and_reviewer_loop(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = $this->makeVulnerability('v1');
        $validatedVuln = $vulnerability->withReviewerValidation(true);

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability], []);

        $this->reviewerAgent
            ->method('review')
            ->willReturn([$validatedVuln]);

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
        self::assertCount(1, $auditContext->validatedVulnerabilities());
    }

    public function test_it_stops_when_attacker_finds_nothing(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $this->attackerAgent
            ->expects(self::once())
            ->method('analyze')
            ->willReturn([]);

        $this->reviewerAgent->expects(self::never())->method('review');

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_deduplicates_vulnerabilities_across_iterations(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = $this->makeVulnerability('v1');
        $validated = $vulnerability->withReviewerValidation(true);

        $this->attackerAgent
            ->method('analyze')
            ->willReturn([$vulnerability]);

        $this->reviewerAgent
            ->method('review')
            ->willReturn([$validated]);

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_it_filters_low_confidence_findings(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = $this->makeVulnerability('low', confidence: 0.3);

        $this->attackerAgent
            ->expects(self::once())
            ->method('analyze')
            ->willReturn([$vulnerability]);

        $this->reviewerAgent->expects(self::never())->method('review');

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_stores_audit_metadata_in_context(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $this->attackerAgent->method('analyze')->willReturn([]);

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertNotNull($auditContext->getMeta('audit.iterations'));
        self::assertNotNull($auditContext->getMeta('audit.total_findings'));
        self::assertNotNull($auditContext->getMeta('audit.validated'));
        self::assertNotNull($auditContext->getMeta('audit.risk_score'));
    }

    public function test_it_runs_exactly_max_iterations_when_new_findings_each_time(): void
    {
        $auditContext = $this->makeContextWithMapping();
        $iterationCount = 0;

        $this->attackerAgent
            ->method('analyze')
            ->willReturnCallback(static function () use (&$iterationCount): array {
                ++$iterationCount;

                return [Vulnerability::create(
                    VulnerabilityType::SQL_INJECTION,
                    VulnerabilitySeverity::HIGH,
                    'Vuln iter'.$iterationCount,
                    'desc',
                    'src/File'.$iterationCount.'.php',
                    10, 15,
                    '$q', 'inject', "' OR 1", 'fix',
                    0.9,
                )];
            });

        $this->reviewerAgent
            ->method('review')
            ->willReturnCallback(static function (array $vulns): array {
                $result = [];
                foreach ($vulns as $vuln) {
                    Assert::assertInstanceOf(Vulnerability::class, $vuln);
                    $result[] = $vuln->withReviewerValidation(true);
                }

                return $result;
            });

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertSame(3, $auditContext->getMeta('audit.iterations'));
    }

    public function test_it_accepts_vulnerability_at_exact_confidence_threshold(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = $this->makeVulnerability('threshold', confidence: 0.6);

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability], []);

        $this->reviewerAgent
            ->method('review')
            ->willReturn([$vulnerability->withReviewerValidation(true)]);

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_it_rejects_vulnerability_just_below_confidence_threshold(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = $this->makeVulnerability('below', confidence: 0.59);

        $this->attackerAgent
            ->expects(self::once())
            ->method('analyze')
            ->willReturn([$vulnerability]);

        $this->reviewerAgent->expects(self::never())->method('review');

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_deduplicates_by_overlapping_line_ranges(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = Vulnerability::create(
            VulnerabilityType::SQL_INJECTION,
            VulnerabilitySeverity::HIGH,
            'SQL Injection A',
            'desc',
            'src/Controller/FooController.php',
            10, 20,
            '$q', 'inject', "' OR 1", 'fix',
            0.9,
        );
        $vuln2 = Vulnerability::create(
            VulnerabilityType::SQL_INJECTION,
            VulnerabilitySeverity::HIGH,
            'SQL Injection B',
            'desc',
            'src/Controller/FooController.php',
            15, 25,
            '$q', 'inject', "' OR 1", 'fix',
            0.9,
        );

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability], [$vuln2]);

        $this->reviewerAgent
            ->method('review')
            ->willReturnCallback(static function (array $vulns): array {
                $result = [];
                foreach ($vulns as $vuln) {
                    Assert::assertInstanceOf(Vulnerability::class, $vuln);
                    $result[] = $vuln->withReviewerValidation(true);
                }

                return $result;
            });

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_it_stores_exact_metadata_values_after_orchestration(): void
    {
        $auditContext = $this->makeContextWithMapping();
        $vulnerability = $this->makeVulnerability('v1');
        $validated = $vulnerability->withReviewerValidation(true);

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability], []);

        $this->reviewerAgent
            ->method('review')
            ->willReturn([$validated]);

        $this->auditOrchestrator->orchestrate($auditContext);

        self::assertSame(2, $auditContext->getMeta('audit.iterations'));
        self::assertSame(1, $auditContext->getMeta('audit.total_findings'));
        self::assertSame(1, $auditContext->getMeta('audit.validated'));
        self::assertSame(7, $auditContext->getMeta('audit.risk_score'));
    }

    public function test_it_continues_processing_remaining_reviewed_findings_after_duplicate(): void
    {
        // If continue→break mutation occurred, processing would stop after the duplicate.
        // This test ensures that when a dup is encountered, processing continues to the next item.
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = $this->makeVulnerability('dup');
        $new = $this->makeVulnerability('new', lineStart: 20, lineEnd: 30);

        $validated_dup = $vulnerability->withReviewerValidation(true);
        $validated_new = $new->withReviewerValidation(true);

        // First iteration: attacker returns dup only → persisted
        // Second iteration: attacker returns dup+new → dup is duplicate, new should still be added
        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls(
                [$vulnerability],
                [$vulnerability, $new],
                [],
            );

        $this->reviewerAgent
            ->method('review')
            ->willReturnOnConsecutiveCalls(
                [$validated_dup],
                [$validated_dup, $validated_new],
            );

        $this->auditOrchestrator->orchestrate($auditContext);

        // Both unique vulnerabilities should be persisted (not just the first after encountering dup)
        self::assertCount(2, $auditContext->vulnerabilities());
    }

    public function test_lines_overlap_detects_touching_ranges(): void
    {
        // linesOverlap: $start1 <= $end2 && $start2 <= $end1
        // With <= changed to <: touching ranges (end1==start2) would NOT be treated as overlapping.
        // This test ensures end1==start2 IS treated as overlapping (i.e. duplicate).
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = Vulnerability::create(
            VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH,
            'SQL A', 'desc', 'src/Controller/FooController.php',
            10, 20,
            '$q', 'inject', "' OR 1", 'fix', 0.9,
        );
        // start2==20 == end1==20 → touching, should be treated as overlap (duplicate)
        $vuln2 = Vulnerability::create(
            VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH,
            'SQL B', 'desc', 'src/Controller/FooController.php',
            20, 30,
            '$q', 'inject', "' OR 1", 'fix', 0.9,
        );

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability], [$vuln2]);

        $this->reviewerAgent
            ->method('review')
            ->willReturnCallback(static function (array $vulns): array {
                $result = [];
                foreach ($vulns as $vuln) {
                    Assert::assertInstanceOf(Vulnerability::class, $vuln);
                    $result[] = $vuln->withReviewerValidation(true);
                }

                return $result;
            });

        $this->auditOrchestrator->orchestrate($auditContext);

        // vuln2 overlaps with vuln1 (touching at line 20) → deduplicated → only 1 stored
        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_lines_overlap_does_not_deduplicate_non_overlapping_ranges(): void
    {
        // linesOverlap with &&→|| mutation: would treat ALL pairs as overlapping.
        // This test verifies truly separate ranges (1-5 and 10-15) are NOT deduplicated.
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = Vulnerability::create(
            VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH,
            'SQL A', 'desc', 'src/Controller/FooController.php',
            1, 5,
            '$q', 'inject', "' OR 1", 'fix', 0.9,
        );
        $vuln2 = Vulnerability::create(
            VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH,
            'SQL B', 'desc', 'src/Controller/FooController.php',
            10, 15,
            '$q', 'inject', "' OR 1", 'fix', 0.9,
        );

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability], [$vuln2], []);

        $this->reviewerAgent
            ->method('review')
            ->willReturnCallback(static function (array $vulns): array {
                $result = [];
                foreach ($vulns as $vuln) {
                    Assert::assertInstanceOf(Vulnerability::class, $vuln);
                    $result[] = $vuln->withReviewerValidation(true);
                }

                return $result;
            });

        $this->auditOrchestrator->orchestrate($auditContext);

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

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: $logger,
        );

        $auditContext = $this->makeContextWithMapping();
        $vulnerability = $this->makeVulnerability('v1');
        $validated = $vulnerability->withReviewerValidation(true);

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability], []);

        $this->reviewerAgent
            ->method('review')
            ->willReturn([$validated]);

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

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: $logger,
        );

        $auditContext = $this->makeContextWithMapping();
        $this->attackerAgent->method('analyze')->willReturn([]);

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

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: $logger,
        );

        $auditContext = $this->makeContextWithMapping();
        $this->attackerAgent->method('analyze')->willReturn([]);

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

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: $logger,
        );

        $auditContext = $this->makeContextWithMapping();

        $vulnerability = $this->makeVulnerability('v1')->withReviewerValidation(true);
        $rejected = $this->makeVulnerability('v2', lineStart: 30, lineEnd: 40);

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability, $rejected], []);

        $this->reviewerAgent
            ->method('review')
            ->willReturn([$vulnerability, $rejected]);

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

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: $logger,
        );

        $auditContext = $this->makeContextWithMapping();
        $this->attackerAgent->method('analyze')->willReturn([]);

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
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = Vulnerability::create(
            VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH,
            'SQL A', 'desc', 'src/Controller/FooController.php',
            10, 20,
            '$q', 'inject', "' OR 1", 'fix', 0.9,
        );
        $vuln2 = Vulnerability::create(
            VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH,
            'SQL B', 'desc', 'src/Controller/FooController.php',
            5, 10,
            '$q', 'inject', "' OR 1", 'fix', 0.9,
        );

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability], [$vuln2]);

        $this->reviewerAgent
            ->method('review')
            ->willReturnCallback(static function (array $vulns): array {
                $result = [];
                foreach ($vulns as $vuln) {
                    Assert::assertInstanceOf(Vulnerability::class, $vuln);
                    $result[] = $vuln->withReviewerValidation(true);
                }

                return $result;
            });

        $this->auditOrchestrator->orchestrate($auditContext);

        // start1==end2==10 → touching → overlap → dup → only 1 stored
        self::assertCount(1, $auditContext->vulnerabilities());
    }

    public function test_it_logs_warning_when_no_mapping_available(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('No mapping available, skipping audit');

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: $logger,
        );

        $auditContext = AuditContext::forProject($this->tmpDir);
        // No mapping set
        $auditOrchestrator->orchestrate($auditContext);
    }

    public function test_it_respects_custom_max_iterations(): void
    {
        $auditContext = $this->makeContextWithMapping();
        $iterationCount = 0;

        $this->attackerAgent
            ->method('analyze')
            ->willReturnCallback(static function () use (&$iterationCount): array {
                ++$iterationCount;

                return [Vulnerability::create(
                    VulnerabilityType::SQL_INJECTION,
                    VulnerabilitySeverity::HIGH,
                    'Vuln iter'.$iterationCount,
                    'desc',
                    'src/File'.$iterationCount.'.php',
                    10, 15,
                    '$q', 'inject', "' OR 1", 'fix',
                    0.9,
                )];
            });

        $this->reviewerAgent
            ->method('review')
            ->willReturnCallback(static function (array $vulns): array {
                $result = [];
                foreach ($vulns as $vuln) {
                    Assert::assertInstanceOf(Vulnerability::class, $vuln);
                    $result[] = $vuln->withReviewerValidation(true);
                }

                return $result;
            });

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: new NullLogger(),
            maxIterations: 5,
            minConfidence: AuditOrchestrator::DEFAULT_MIN_CONFIDENCE,
        );

        $auditOrchestrator->orchestrate($auditContext);

        self::assertSame(5, $auditContext->getMeta('audit.iterations'));
    }

    public function test_it_respects_custom_min_confidence(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = $this->makeVulnerability('borderline', confidence: 0.65);

        $this->attackerAgent
            ->expects(self::once())
            ->method('analyze')
            ->willReturn([$vulnerability]);

        $this->reviewerAgent->expects(self::never())->method('review');

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: new NullLogger(),
            maxIterations: AuditOrchestrator::DEFAULT_MAX_ITERATIONS,
            minConfidence: 0.7,
        );

        $auditOrchestrator->orchestrate($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
    }

    public function test_it_accepts_vulnerability_at_exact_custom_confidence_threshold(): void
    {
        $auditContext = $this->makeContextWithMapping();

        $vulnerability = $this->makeVulnerability('exact', confidence: 0.7);

        $this->attackerAgent
            ->method('analyze')
            ->willReturnOnConsecutiveCalls([$vulnerability], []);

        $this->reviewerAgent
            ->method('review')
            ->willReturn([$vulnerability->withReviewerValidation(true)]);

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: new NullLogger(),
            maxIterations: AuditOrchestrator::DEFAULT_MAX_ITERATIONS,
            minConfidence: 0.7,
        );

        $auditOrchestrator->orchestrate($auditContext);

        self::assertCount(1, $auditContext->vulnerabilities());
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

        $auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: $logger,
            maxIterations: 7,
            minConfidence: AuditOrchestrator::DEFAULT_MIN_CONFIDENCE,
        );

        $auditContext = $this->makeContextWithMapping();
        $this->attackerAgent->method('analyze')->willReturn([]);

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

        $this->attackerAgent = $this->createMock(AttackerAgentInterface::class);
        $this->reviewerAgent = $this->createMock(ReviewerAgentInterface::class);
        $this->auditOrchestrator = new AuditOrchestrator(
            attackerAgent: $this->attackerAgent,
            reviewerAgent: $this->reviewerAgent,
            logger: new NullLogger(),
        );
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    private function makeContextWithMapping(): AuditContext
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/Controller/Foo.php', '/app/src/Controller/Foo.php', '<?php'),
        ]);
        $auditContext->setMapping(SymfonyMapping::create());

        return $auditContext;
    }

    private function makeVulnerability(string $discriminator, float $confidence = 0.9, int $lineStart = 10, int $lineEnd = 15): Vulnerability
    {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'Vuln '.$discriminator,
            description: 'Test',
            filePath: 'src/Controller/FooController.php',
            lineStart: $lineStart,
            lineEnd: $lineEnd,
            vulnerableCode: '$db->query($input)',
            attackVector: 'SQL injection',
            proof: "' OR 1=1",
            remediation: 'Use prepared statements',
            confidence: $confidence,
        );
    }
}
