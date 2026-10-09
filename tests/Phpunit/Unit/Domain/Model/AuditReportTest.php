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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SecurityGrade;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class AuditReportTest extends TestCase
{
    private string $tmpDir;

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_builds_from_context_with_no_vulnerabilities(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame(0, $auditReport->totalVulnerabilities());
        self::assertSame(0, $auditReport->riskScore());
        self::assertSame('SAFE', $auditReport->riskLevel());
        self::assertSame(0, $auditReport->filesScanned());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_consumed_baseline_fingerprints_default_to_an_empty_list(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame([], $auditReport->consumedBaselineFingerprints());
    }

    /**
     * `BaselineProcessor` needs this to avoid re-spending, at the final-report
     * stage, a baseline credit `AuditOrchestrator` already spent skipping a
     * finding before it ever reached the reviewer.
     *
     * @throws InvalidAuditContextException
     */
    public function test_it_carries_over_the_baseline_credits_consumed_during_the_run(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: ['SSA-AAA']);
        $auditContext->consumeBaselineCredit('SSA-AAA');

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame(['SSA-AAA'], $auditReport->consumedBaselineFingerprints());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_includes_only_validated_vulnerabilities(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::CRITICAL)
            ->withReviewerValidation(true);
        $rejected = $this->makeVulnerability('v2', VulnerabilitySeverity::HIGH)
            ->withReviewerValidation(false);

        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($rejected);

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame(1, $auditReport->totalVulnerabilities());
        self::assertSame(10, $auditReport->riskScore());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_classifies_risk_levels_correctly(): void
    {
        // CRITICAL: score >= 50
        self::assertSame('CRITICAL', $this->reportWithScore(55)->riskLevel());
        // HIGH: score >= 30
        self::assertSame('HIGH', $this->reportWithScore(35)->riskLevel());
        // MEDIUM: score >= 15
        self::assertSame('MEDIUM', $this->reportWithScore(20)->riskLevel());
        // LOW: score >= 5
        self::assertSame('LOW', $this->reportWithScore(8)->riskLevel());
        // SAFE: score < 5
        self::assertSame('SAFE', $this->reportWithScore(0)->riskLevel());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_filters_vulnerabilities_by_severity(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::CRITICAL)->withReviewerValidation(true);
        $high1 = $this->makeVulnerability('v2', VulnerabilitySeverity::HIGH)->withReviewerValidation(true);
        $high2 = $this->makeVulnerability('v3', VulnerabilitySeverity::HIGH)->withReviewerValidation(true);
        $medium = $this->makeVulnerability('v4', VulnerabilitySeverity::MEDIUM)->withReviewerValidation(true);

        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($high1);
        $auditContext->addVulnerability($high2);
        $auditContext->addVulnerability($medium);

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertCount(1, $auditReport->vulnerabilitiesBySeverity(VulnerabilitySeverity::CRITICAL));
        self::assertCount(2, $auditReport->vulnerabilitiesBySeverity(VulnerabilitySeverity::HIGH));
        self::assertCount(1, $auditReport->vulnerabilitiesBySeverity(VulnerabilitySeverity::MEDIUM));
        self::assertCount(0, $auditReport->vulnerabilitiesBySeverity(VulnerabilitySeverity::LOW));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_filters_vulnerabilities_by_type(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::HIGH, VulnerabilityType::SQL_INJECTION)
            ->withReviewerValidation(true);
        $bac = $this->makeVulnerability('v2', VulnerabilitySeverity::CRITICAL, VulnerabilityType::BROKEN_ACCESS_CONTROL)
            ->withReviewerValidation(true);

        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($bac);

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertCount(1, $auditReport->vulnerabilitiesByType(VulnerabilityType::SQL_INJECTION));
        self::assertCount(1, $auditReport->vulnerabilitiesByType(VulnerabilityType::BROKEN_ACCESS_CONTROL));
        self::assertCount(0, $auditReport->vulnerabilitiesByType(VulnerabilityType::SSRF));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_vulnerabilities_are_ordered_most_severe_first(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $discoveryOrder = [
            VulnerabilitySeverity::LOW,
            VulnerabilitySeverity::INFO,
            VulnerabilitySeverity::CRITICAL,
            VulnerabilitySeverity::MEDIUM,
            VulnerabilitySeverity::HIGH,
        ];
        foreach ($discoveryOrder as $index => $severity) {
            $auditContext->addVulnerability(
                $this->makeVulnerability('order'.$index, $severity)->withReviewerValidation(true),
            );
        }

        $severities = array_map(
            static fn (Vulnerability $vulnerability): VulnerabilitySeverity => $vulnerability->severity(),
            AuditReport::fromContext($auditContext)->vulnerabilities(),
        );

        self::assertSame(
            [
                VulnerabilitySeverity::CRITICAL,
                VulnerabilitySeverity::HIGH,
                VulnerabilitySeverity::MEDIUM,
                VulnerabilitySeverity::LOW,
                VulnerabilitySeverity::INFO,
            ],
            $severities,
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_vulnerabilities_with_equal_severity_keep_discovery_order(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditContext->addVulnerability($this->makeVulnerability('firstHigh', VulnerabilitySeverity::HIGH)->withReviewerValidation(true));
        $auditContext->addVulnerability($this->makeVulnerability('low', VulnerabilitySeverity::LOW)->withReviewerValidation(true));
        $auditContext->addVulnerability($this->makeVulnerability('secondHigh', VulnerabilitySeverity::HIGH)->withReviewerValidation(true));

        $filePaths = array_map(
            static fn (Vulnerability $vulnerability): string => $vulnerability->filePath(),
            AuditReport::fromContext($auditContext)->vulnerabilities(),
        );

        self::assertSame(['src/firstHigh.php', 'src/secondHigh.php', 'src/low.php'], $filePaths);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_serializes_to_array(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);
        $array = $auditReport->toArray();

        self::assertArrayHasKey('audit_id', $array);
        self::assertArrayHasKey('project', $array);
        self::assertArrayHasKey('started_at', $array);
        self::assertArrayHasKey('completed_at', $array);
        self::assertArrayHasKey('duration_seconds', $array);
        self::assertArrayHasKey('files_scanned', $array);
        self::assertArrayHasKey('risk_score', $array);
        self::assertArrayHasKey('risk_level', $array);
        self::assertArrayHasKey('total_vulnerabilities', $array);
        self::assertArrayHasKey('by_severity', $array);
        self::assertArrayHasKey('vulnerabilities', $array);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_serializes_the_score_and_grade_alongside_the_unchanged_risk_fields(): void
    {
        $array = $this->reportWithExactScore(29)->toArray();

        self::assertSame(
            ['risk_score' => 29, 'risk_level' => 'MEDIUM', 'score' => 71, 'grade' => 'C'],
            [
                'risk_score' => $array['risk_score'],
                'risk_level' => $array['risk_level'],
                'score' => $array['score'],
                'grade' => $array['grade'],
            ],
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_calculates_duration(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);

        self::assertGreaterThanOrEqual(0.0, $auditReport->durationSeconds());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_duration_uses_subtraction_not_addition(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);

        self::assertLessThan(1.0, $auditReport->durationSeconds());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_duration_preserves_sub_second_precision_instead_of_rounding_to_whole_seconds(): void
    {
        $before = microtime(true);
        $auditContext = AuditContext::forProject($this->tmpDir);
        usleep(50_000);
        $auditReport = AuditReport::fromContext($auditContext);
        $measuredElapsed = microtime(true) - $before;

        self::assertEqualsWithDelta($measuredElapsed, $auditReport->durationSeconds(), 0.03);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_classifies_risk_level_at_exact_boundaries(): void
    {
        self::assertSame('CRITICAL', $this->reportWithExactScore(50)->riskLevel());
        self::assertSame('HIGH', $this->reportWithExactScore(49)->riskLevel());
        self::assertSame('HIGH', $this->reportWithExactScore(30)->riskLevel());
        self::assertSame('MEDIUM', $this->reportWithExactScore(29)->riskLevel());
        self::assertSame('MEDIUM', $this->reportWithExactScore(15)->riskLevel());
        self::assertSame('LOW', $this->reportWithExactScore(14)->riskLevel());
        self::assertSame('LOW', $this->reportWithExactScore(5)->riskLevel());
        self::assertSame('SAFE', $this->reportWithExactScore(4)->riskLevel());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('riskLevelEnumCases')]
    public function test_risk_level_enum_classifies_by_aggregate_score(int $score, RiskLevel $riskLevel): void
    {
        self::assertSame($riskLevel, $this->reportWithExactScore($score)->riskLevelEnum());
    }

    /**
     * @return iterable<string, array{int, RiskLevel}>
     */
    public static function riskLevelEnumCases(): iterable
    {
        yield 'critical at 50' => [50, RiskLevel::Critical];
        yield 'high at 49' => [49, RiskLevel::High];
        yield 'high at 30' => [30, RiskLevel::High];
        yield 'medium at 29' => [29, RiskLevel::Medium];
        yield 'medium at 15' => [15, RiskLevel::Medium];
        yield 'low at 14' => [14, RiskLevel::Low];
        yield 'low at 5' => [5, RiskLevel::Low];
        yield 'safe at 4' => [4, RiskLevel::Safe];
        yield 'safe at 0' => [0, RiskLevel::Safe];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('normalizedScoreCases')]
    public function test_normalized_score_deducts_the_aggregate_risk_from_a_hundred(int $score, int $expectedNormalizedScore): void
    {
        self::assertSame($expectedNormalizedScore, $this->reportWithExactScore($score)->normalizedScore());
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function normalizedScoreCases(): iterable
    {
        yield 'a clean report scores a hundred' => [0, 100];
        yield 'a single low finding costs two points' => [2, 98];
        yield 'the safe ceiling' => [4, 96];
        yield 'the low ceiling' => [14, 86];
        yield 'the medium ceiling' => [29, 71];
        yield 'the high ceiling' => [49, 51];
        yield 'the critical floor' => [50, 50];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_normalized_score_is_clamped_at_zero_for_an_overwhelming_risk_score(): void
    {
        self::assertSame(0, $this->reportWithExactScore(140)->normalizedScore());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('gradeCases')]
    public function test_grade_agrees_with_the_risk_level_at_every_boundary(int $score, SecurityGrade $securityGrade): void
    {
        self::assertSame($securityGrade, $this->reportWithExactScore($score)->grade());
    }

    /**
     * @return iterable<string, array{int, SecurityGrade}>
     */
    public static function gradeCases(): iterable
    {
        yield 'safe is an A' => [0, SecurityGrade::A];
        yield 'the safe ceiling is an A' => [4, SecurityGrade::A];
        yield 'the low floor is a B' => [5, SecurityGrade::B];
        yield 'the low ceiling is a B' => [14, SecurityGrade::B];
        yield 'the medium floor is a C' => [15, SecurityGrade::C];
        yield 'the medium ceiling is a C' => [29, SecurityGrade::C];
        yield 'the high floor is a D' => [30, SecurityGrade::D];
        yield 'the high ceiling is a D' => [49, SecurityGrade::D];
        yield 'the critical floor is an F' => [50, SecurityGrade::F];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_risk_level_string_is_the_uppercased_enum_value(): void
    {
        self::assertSame('CRITICAL', $this->reportWithExactScore(50)->riskLevel());
        self::assertSame('SAFE', $this->reportWithExactScore(0)->riskLevel());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_toarray_vulnerabilities_is_array_of_arrays(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->makeVulnerability('v1', VulnerabilitySeverity::HIGH)
            ->withReviewerValidation(true);
        $auditContext->addVulnerability($vulnerability);

        $auditReport = AuditReport::fromContext($auditContext);
        $array = $auditReport->toArray();

        self::assertIsArray($array['vulnerabilities']);
        self::assertCount(1, $array['vulnerabilities']);
        self::assertIsArray($array['vulnerabilities'][0]);
        self::assertArrayHasKey('title', $array['vulnerabilities'][0]);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_report_carries_coverage_from_context(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $auditContext->recordCoverage('reviewer', 'src/A.php', 'validated');

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame(
            [
                ['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'analyzed'],
                ['stage' => 'reviewer', 'file' => 'src/A.php', 'status' => 'validated'],
            ],
            $auditReport->coverage(),
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_report_array_includes_coverage_key(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');

        $array = AuditReport::fromContext($auditContext)->toArray();

        self::assertArrayHasKey('coverage', $array);
        self::assertSame(
            [['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'analyzed']],
            $array['coverage'],
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_names_each_file_a_stage_never_finished_analyzing_once(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', 'src/Analyzed.php', 'analyzed');
        $auditContext->recordCoverage('attacker', 'src/Errored.php', 'errored');
        $auditContext->recordCoverage('attacker', 'src/Aborted.php', 'aborted');
        $auditContext->recordCoverage('reviewer', 'src/Errored.php', 'errored');
        $auditContext->recordCoverage('attacker', 'src/Skipped.php', 'skipped');
        $auditContext->recordCoverage('attacker', 'src/Cached.php', 'cached');
        $auditContext->recordCoverage('reviewer', 'src/Rejected.php', 'rejected');
        $auditContext->recordCoverage('reviewer', 'src/Analyzed.php', 'validated');

        self::assertSame(['src/Errored.php', 'src/Aborted.php'], AuditReport::fromContext($auditContext)->unanalyzedFiles());
    }

    /**
     * @throws InvalidAuditContextException
     */
    #[DataProvider('completenessCases')]
    public function test_it_is_complete_only_when_every_file_was_analyzed(string $status, bool $expected): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', 'src/A.php', $status);

        self::assertSame($expected, AuditReport::fromContext($auditContext)->isComplete());
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function completenessCases(): iterable
    {
        yield 'an analyzed file' => ['analyzed', true];
        yield 'a file the lean filter skipped on purpose' => ['skipped', true];
        yield 'a file whose call failed' => ['errored', false];
        yield 'a file an abort never reached' => ['aborted', false];
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_report_array_says_whether_the_audit_is_complete(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', 'src/A.php', 'errored');

        self::assertFalse(AuditReport::fromContext($auditContext)->toArray()['complete']);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_report_coverage_is_empty_when_context_recorded_nothing(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame([], $auditReport->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_completed_at_is_at_or_after_started_at(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);

        self::assertGreaterThanOrEqual(
            $auditReport->startedAt()->getTimestamp(),
            $auditReport->completedAt()->getTimestamp(),
        );
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/report_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function reportWithExactScore(int $score): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $i = 0;
        $pairs = [
            [VulnerabilitySeverity::CRITICAL, 10],
            [VulnerabilitySeverity::HIGH, 7],
            [VulnerabilitySeverity::MEDIUM, 5],
            [VulnerabilitySeverity::LOW, 2],
        ];
        foreach ($pairs as [$severity, $points]) {
            while ($score >= $points) {
                $auditContext->addVulnerability(
                    $this->makeVulnerability('b'.($i++), $severity)->withReviewerValidation(true),
                );
                $score -= $points;
            }
        }

        return AuditReport::fromContext($auditContext);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function reportWithScore(int $targetScore): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        // Add critical vulns (score 10 each) to hit target
        $count = (int) ceil($targetScore / 10);
        for ($i = 0; $i < $count; ++$i) {
            $v = $this->makeVulnerability('vs'.$i, VulnerabilitySeverity::CRITICAL)
                ->withReviewerValidation(true);
            $auditContext->addVulnerability($v);
        }

        return AuditReport::fromContext($auditContext);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_fingerprints_lists_each_distinct_finding(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->makeVulnerability('a', VulnerabilitySeverity::HIGH)->withReviewerValidation(true);
        $second = $this->makeVulnerability('b', VulnerabilitySeverity::LOW)->withReviewerValidation(true);
        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($second);

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertEqualsCanonicalizing([$vulnerability->fingerprint(), $second->fingerprint()], $auditReport->fingerprints());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_fingerprints_deduplicates_findings_that_share_a_fingerprint(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->sameFingerprintVuln(1)->withReviewerValidation(true));
        $auditContext->addVulnerability($this->sameFingerprintVuln(2)->withReviewerValidation(true));

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertCount(1, $auditReport->fingerprints());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_without_fingerprints_removes_only_matching_findings(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->makeVulnerability('keep', VulnerabilitySeverity::HIGH)->withReviewerValidation(true);
        $dropped = $this->makeVulnerability('drop', VulnerabilitySeverity::HIGH)->withReviewerValidation(true);
        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($dropped);

        $auditReport = AuditReport::fromContext($auditContext)->withoutFingerprints([$dropped->fingerprint()]);

        self::assertSame(1, $auditReport->totalVulnerabilities());
        self::assertSame($vulnerability->fingerprint(), $auditReport->vulnerabilities()[0]->fingerprint());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_without_fingerprints_keeps_findings_absent_from_the_list(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability('a', VulnerabilitySeverity::HIGH)->withReviewerValidation(true));
        $auditContext->addVulnerability($this->makeVulnerability('b', VulnerabilitySeverity::HIGH)->withReviewerValidation(true));

        $auditReport = AuditReport::fromContext($auditContext)->withoutFingerprints(['SSA-DOESNOTEXIST']);

        self::assertSame(2, $auditReport->totalVulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_without_fingerprints_only_removes_as_many_shared_fingerprint_findings_as_were_accepted(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->sameFingerprintVuln(1)->withReviewerValidation(true);
        $unrelated = $this->sameFingerprintVuln(2)->withReviewerValidation(true);
        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($unrelated);

        $auditReport = AuditReport::fromContext($auditContext)->withoutFingerprints([$vulnerability->fingerprint()]);

        self::assertSame(1, $auditReport->totalVulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_without_fingerprints_preserves_report_metadata(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability('a', VulnerabilitySeverity::HIGH)->withReviewerValidation(true));

        $auditReport = AuditReport::fromContext($auditContext);

        $filtered = $auditReport->withoutFingerprints($auditReport->fingerprints());

        self::assertSame(0, $filtered->totalVulnerabilities());
        self::assertSame($auditReport->auditId(), $filtered->auditId());
        self::assertSame($auditReport->projectPath(), $filtered->projectPath());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_filtered_by_types_with_no_filters_keeps_all_findings(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::SQL_INJECTION, VulnerabilityType::SSRF);

        self::assertSame(2, $auditReport->filteredByTypes([], [])->totalVulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_filtered_by_types_drops_excluded_types(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::SQL_INJECTION, VulnerabilityType::SSRF);

        $filtered = $auditReport->filteredByTypes([], [VulnerabilityType::SQL_INJECTION]);

        self::assertSame([VulnerabilityType::SSRF], $this->typesOf($filtered));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_filtered_by_types_with_an_allowlist_keeps_only_included_types(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::SQL_INJECTION, VulnerabilityType::SSRF, VulnerabilityType::MISSING_RATE_LIMITING);

        $filtered = $auditReport->filteredByTypes([VulnerabilityType::SSRF], []);

        self::assertSame([VulnerabilityType::SSRF], $this->typesOf($filtered));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_filtered_by_types_lets_exclusions_win_over_the_allowlist(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::SQL_INJECTION, VulnerabilityType::SSRF);

        $filtered = $auditReport->filteredByTypes(
            [VulnerabilityType::SQL_INJECTION, VulnerabilityType::SSRF],
            [VulnerabilityType::SQL_INJECTION],
        );

        self::assertSame([VulnerabilityType::SSRF], $this->typesOf($filtered));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_filtered_by_types_preserves_report_metadata(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::SQL_INJECTION);

        $filtered = $auditReport->filteredByTypes([], [VulnerabilityType::SQL_INJECTION]);

        self::assertSame(0, $filtered->totalVulnerabilities());
        self::assertSame($auditReport->auditId(), $filtered->auditId());
        self::assertSame($auditReport->projectPath(), $filtered->projectPath());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function reportWithTypes(VulnerabilityType ...$types): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        foreach ($types as $index => $type) {
            $auditContext->addVulnerability(
                $this->makeVulnerability('t'.$index, VulnerabilitySeverity::HIGH, $type)->withReviewerValidation(true),
            );
        }

        return AuditReport::fromContext($auditContext);
    }

    /**
     * @return list<VulnerabilityType>
     */
    private function typesOf(AuditReport $auditReport): array
    {
        return array_map(
            static fn (Vulnerability $vulnerability): VulnerabilityType => $vulnerability->type(),
            $auditReport->vulnerabilities(),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function sameFingerprintVuln(int $lineStart): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Shared title', 0.9),
            new CodeLocation('src/Shared.php', $lineStart, $lineStart + 1),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            'code',
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerability(
        string $discriminator,
        VulnerabilitySeverity $vulnerabilitySeverity,
        VulnerabilityType $vulnerabilityType = VulnerabilityType::SQL_INJECTION,
    ): Vulnerability {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, $vulnerabilitySeverity, 'Test '.$discriminator, 0.9),
            new CodeLocation('src/'.$discriminator.'.php', 1, 5),
            new VulnerabilityNarrative('Test vulnerability', 'Inject', "' OR 1=1", 'Fix it'),
            '$query',
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_the_attacker_finished_on_a_later_iteration_counts_as_analyzed(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', 'src/A.php', 'errored');
        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame([], $auditReport->unanalyzedFiles());
        self::assertTrue($auditReport->isComplete());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_served_from_cache_after_a_failed_iteration_counts_as_analyzed(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', 'src/A.php', 'aborted');
        $auditContext->recordCoverage('attacker', 'src/A.php', 'cached');

        self::assertTrue(AuditReport::fromContext($auditContext)->isComplete());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_file_the_scan_left_out_is_listed_in_the_coverage_and_leaves_the_report_complete(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([ProjectFile::create('src/A.php', $this->tmpDir.'/src/A.php', '<?php')]);
        $auditContext->recordCoverage('scan', 'src/Big.php', 'skipped');
        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame(
            [
                ['stage' => 'scan', 'file' => 'src/Big.php', 'status' => 'skipped'],
                ['stage' => 'attacker', 'file' => 'src/A.php', 'status' => 'analyzed'],
            ],
            $auditReport->coverage(),
        );
        self::assertSame([], $auditReport->unanalyzedFiles());
        self::assertTrue($auditReport->isComplete());
        self::assertFalse($auditReport->hasNoVerdict());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_file_the_attacker_failed_on_a_later_iteration_counts_as_unanalyzed(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $auditContext->recordCoverage('attacker', 'src/A.php', 'errored');

        self::assertSame(['src/A.php'], AuditReport::fromContext($auditContext)->unanalyzedFiles());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_reviewer_failure_counts_however_a_later_review_of_the_same_file_went(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $auditContext->recordCoverage('reviewer', 'src/A.php', 'errored');
        $auditContext->recordCoverage('reviewer', 'src/A.php', 'validated');

        self::assertSame(['src/A.php'], AuditReport::fromContext($auditContext)->unanalyzedFiles());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_pipeline_that_records_no_coverage_keeps_a_complete_report(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([ProjectFile::create('src/A.php', $this->tmpDir.'/src/A.php', '<?php')]);

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertTrue($auditReport->isComplete());
        self::assertFalse($auditReport->hasNoVerdict());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_cost_estimate_of_the_files_in_scope_never_reads_as_complete(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([ProjectFile::create('src/A.php', $this->tmpDir.'/src/A.php', '<?php')]);
        $auditContext->markAsCostEstimate();

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertFalse($auditReport->isComplete());
        self::assertTrue($auditReport->hasNoVerdict());
        self::assertSame([], $auditReport->unanalyzedFiles());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_cost_estimate_with_no_file_in_scope_has_nothing_left_unanalyzed(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->markAsCostEstimate();

        self::assertTrue(AuditReport::fromContext($auditContext)->isComplete());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_diff_run_that_left_no_file_to_analyze_stays_complete(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setMappingFiles([ProjectFile::create('src/A.php', $this->tmpDir.'/src/A.php', '<?php')]);

        self::assertTrue(AuditReport::fromContext($auditContext)->isComplete());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_scan_that_discovered_no_file_has_no_verdict(): void
    {
        $auditReport = AuditReport::fromContext(AuditContext::forProject($this->tmpDir));

        self::assertSame(0, $auditReport->filesDiscovered());
        self::assertTrue($auditReport->hasNoVerdict());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_diff_run_that_left_no_file_to_analyze_still_has_a_verdict(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setMappingFiles([ProjectFile::create('src/A.php', $this->tmpDir.'/src/A.php', '<?php')]);

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame(0, $auditReport->filesScanned());
        self::assertFalse($auditReport->hasNoVerdict());
    }

    /**
     * @param list<array{string, string, string}> $coverage
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('noVerdictCases')]
    public function test_it_knows_when_the_run_reached_no_verdict(array $coverage, bool $expected): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/A.php', $this->tmpDir.'/src/A.php', '<?php'),
            ProjectFile::create('src/B.php', $this->tmpDir.'/src/B.php', '<?php'),
        ]);
        foreach ($coverage as [$stage, $file, $status]) {
            $auditContext->recordCoverage($stage, $file, $status);
        }

        self::assertSame($expected, AuditReport::fromContext($auditContext)->hasNoVerdict());
    }

    /**
     * @return iterable<string, array{list<array{string, string, string}>, bool}>
     */
    public static function noVerdictCases(): iterable
    {
        yield 'every call failed' => [[['attacker', 'src/A.php', 'errored'], ['attacker', 'src/B.php', 'aborted']], true];
        yield 'a pipeline that records no coverage' => [[], false];
        yield 'one file analyzed, the other failed' => [[['attacker', 'src/A.php', 'analyzed'], ['attacker', 'src/B.php', 'errored']], false];
        yield 'one file served from the cache, the other failed' => [[['attacker', 'src/A.php', 'cached'], ['attacker', 'src/B.php', 'errored']], false];
        yield 'a file analyzed before a later iteration failed on it' => [[['attacker', 'src/A.php', 'analyzed'], ['attacker', 'src/A.php', 'errored'], ['attacker', 'src/B.php', 'errored']], false];
        yield 'every file analyzed' => [[['attacker', 'src/A.php', 'analyzed'], ['attacker', 'src/B.php', 'analyzed']], false];
        yield 'every file left out by the lean filter' => [[['attacker', 'src/A.php', 'skipped'], ['attacker', 'src/B.php', 'skipped']], false];
        yield 'lean filter left one out, the other failed' => [[['attacker', 'src/A.php', 'skipped'], ['attacker', 'src/B.php', 'errored']], true];
        yield 'only another stage claims to have analyzed a file' => [[['attacker', 'src/A.php', 'errored'], ['attacker', 'src/B.php', 'errored'], ['reviewer', 'src/A.php', 'analyzed']], true];
    }

    /**
     * A response cut short keeps the findings it recorded while its chunk is
     * recorded as errored, so a run can hold a finding without having fully
     * analyzed any file: that is a partial run, never one without a verdict.
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_run_that_analyzed_no_file_yet_holds_a_finding_has_a_verdict(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([ProjectFile::create('src/A.php', $this->tmpDir.'/src/A.php', '<?php')]);
        $auditContext->recordCoverage('attacker', 'src/A.php', 'errored');
        $auditContext->addVulnerability(Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Kept from a response cut short', 0.9),
            new CodeLocation('src/A.php', 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            '$code',
        )->withReviewerValidation(true));

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertFalse($auditReport->isComplete());
        self::assertFalse($auditReport->hasNoVerdict());
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidAuditContextException
     */
    #[DataProvider('runScopes')]
    public function test_the_array_form_records_the_scope_of_the_run(array $scanPaths, ?string $diffSinceRef): void
    {
        $toArray = AuditReport::fromContext(AuditContext::forProject($this->tmpDir, $scanPaths, diffSinceRef: $diffSinceRef))->toArray();

        self::assertSame(['since' => $diffSinceRef, 'paths' => $scanPaths], $toArray['scope']);
    }

    /**
     * @return iterable<string, array{list<string>, ?string}>
     */
    public static function runScopes(): iterable
    {
        yield 'the whole project over its whole history' => [[], null];
        yield 'two --path scopes since a git ref' => [['src/Controller', 'config'], 'origin/main'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_array_form_lists_no_suppressed_fingerprint_when_nothing_was_withheld(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability('a', VulnerabilitySeverity::HIGH)->withReviewerValidation(true));

        self::assertSame([], AuditReport::fromContext($auditContext)->toArray()['suppressed_fingerprints']);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_the_array_form_lists_the_baseline_credits_spent_before_the_review(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: ['SSA-AAA', 'SSA-BBB', 'SSA-CCC']);
        $auditContext->consumeBaselineCredit('SSA-BBB');
        $auditContext->consumeBaselineCredit('SSA-AAA');

        self::assertSame(['SSA-BBB', 'SSA-AAA'], AuditReport::fromContext($auditContext)->toArray()['suppressed_fingerprints']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_array_form_lists_a_finding_the_baseline_removed_but_not_one_it_kept(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability('keep', VulnerabilitySeverity::HIGH)->withReviewerValidation(true));

        $vulnerability = $this->makeVulnerability('drop', VulnerabilitySeverity::HIGH)->withReviewerValidation(true);
        $auditContext->addVulnerability($vulnerability);

        $auditReport = AuditReport::fromContext($auditContext)->withoutFingerprints([$vulnerability->fingerprint()]);

        self::assertSame([$vulnerability->fingerprint()], $auditReport->toArray()['suppressed_fingerprints']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_array_form_lists_a_shared_fingerprint_once_per_occurrence_the_baseline_removed(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->sameFingerprintVuln(1)->withReviewerValidation(true);
        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($this->sameFingerprintVuln(2)->withReviewerValidation(true));
        $auditContext->addVulnerability($this->sameFingerprintVuln(3)->withReviewerValidation(true));

        $auditReport = AuditReport::fromContext($auditContext);

        $suppressed = $auditReport->withoutFingerprints([$vulnerability->fingerprint(), $vulnerability->fingerprint()])->toArray()['suppressed_fingerprints'];

        self::assertSame([$vulnerability->fingerprint(), $vulnerability->fingerprint()], $suppressed);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_array_form_lists_a_finding_the_type_filter_removed_but_not_one_it_kept(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->makeVulnerability('muted', VulnerabilitySeverity::HIGH, VulnerabilityType::SQL_INJECTION)->withReviewerValidation(true);
        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($this->makeVulnerability('shown', VulnerabilitySeverity::HIGH, VulnerabilityType::SSRF)->withReviewerValidation(true));

        $auditReport = AuditReport::fromContext($auditContext)->filteredByTypes([], [VulnerabilityType::SQL_INJECTION]);

        self::assertSame([$vulnerability->fingerprint()], $auditReport->toArray()['suppressed_fingerprints']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_array_form_lists_the_findings_an_allowlist_left_out(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $vulnerability = $this->makeVulnerability('left-out', VulnerabilitySeverity::HIGH, VulnerabilityType::SQL_INJECTION)->withReviewerValidation(true);
        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($this->makeVulnerability('listed', VulnerabilitySeverity::HIGH, VulnerabilityType::SSRF)->withReviewerValidation(true));

        $auditReport = AuditReport::fromContext($auditContext)->filteredByTypes([VulnerabilityType::SSRF], []);

        self::assertSame([$vulnerability->fingerprint()], $auditReport->toArray()['suppressed_fingerprints']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_array_form_lists_every_withheld_finding_in_the_order_the_run_withheld_it(): void
    {
        $vulnerability = $this->makeVulnerability('muted', VulnerabilitySeverity::HIGH, VulnerabilityType::SSRF)->withReviewerValidation(true);
        $accepted = $this->makeVulnerability('accepted', VulnerabilitySeverity::HIGH)->withReviewerValidation(true);
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: ['SSA-SKIPPED']);
        $auditContext->consumeBaselineCredit('SSA-SKIPPED');
        $auditContext->addVulnerability($vulnerability);
        $auditContext->addVulnerability($accepted);

        $auditReport = AuditReport::fromContext($auditContext)
            ->filteredByTypes([], [VulnerabilityType::SSRF])
            ->withoutFingerprints([$accepted->fingerprint()]);

        self::assertSame(['SSA-SKIPPED', $vulnerability->fingerprint(), $accepted->fingerprint()], $auditReport->toArray()['suppressed_fingerprints']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_finding_removed_after_the_review_leaves_the_baseline_credits_spent_before_it_alone(): void
    {
        $vulnerability = $this->makeVulnerability('removed', VulnerabilitySeverity::HIGH)->withReviewerValidation(true);
        $auditContext = AuditContext::forProject($this->tmpDir, acceptedFingerprints: ['SSA-SKIPPED']);
        $auditContext->consumeBaselineCredit('SSA-SKIPPED');
        $auditContext->addVulnerability($vulnerability);

        $auditReport = AuditReport::fromContext($auditContext)
            ->filteredByTypes([], [VulnerabilityType::SQL_INJECTION])
            ->withoutFingerprints([$vulnerability->fingerprint()]);

        self::assertSame(['SSA-SKIPPED'], $auditReport->consumedBaselineFingerprints());
    }
}
