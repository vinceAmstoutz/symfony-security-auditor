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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
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
}
