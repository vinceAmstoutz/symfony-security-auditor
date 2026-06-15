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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class AuditReportTest extends TestCase
{
    private string $tmpDir;

    public function test_it_builds_from_context_with_no_vulnerabilities(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame(0, $auditReport->totalVulnerabilities());
        self::assertSame(0, $auditReport->riskScore());
        self::assertSame('SAFE', $auditReport->riskLevel());
        self::assertSame(0, $auditReport->filesScanned());
    }

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

    public function test_it_calculates_duration(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);

        self::assertGreaterThanOrEqual(0.0, $auditReport->durationSeconds());
    }

    public function test_duration_uses_subtraction_not_addition(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);

        self::assertLessThan(1.0, $auditReport->durationSeconds());
    }

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

    public function test_report_coverage_is_empty_when_context_recorded_nothing(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame([], $auditReport->coverage());
    }

    public function test_completed_at_is_at_or_after_started_at(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);

        self::assertGreaterThanOrEqual(
            $auditReport->startedAt()->getTimestamp(),
            $auditReport->completedAt()->getTimestamp(),
        );
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/report_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

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

    public function test_fingerprints_deduplicates_findings_that_share_a_fingerprint(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->sameFingerprintVuln(1)->withReviewerValidation(true));
        $auditContext->addVulnerability($this->sameFingerprintVuln(2)->withReviewerValidation(true));

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertCount(1, $auditReport->fingerprints());
    }

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

    public function test_without_fingerprints_keeps_findings_absent_from_the_list(): void
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->addVulnerability($this->makeVulnerability('a', VulnerabilitySeverity::HIGH)->withReviewerValidation(true));
        $auditContext->addVulnerability($this->makeVulnerability('b', VulnerabilitySeverity::HIGH)->withReviewerValidation(true));

        $auditReport = AuditReport::fromContext($auditContext)->withoutFingerprints(['SSA-DOESNOTEXIST']);

        self::assertSame(2, $auditReport->totalVulnerabilities());
    }

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

    private function sameFingerprintVuln(int $lineStart): Vulnerability
    {
        return Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'Shared title',
            description: 'desc',
            filePath: 'src/Shared.php',
            lineStart: $lineStart,
            lineEnd: $lineStart + 1,
            vulnerableCode: 'code',
            attackVector: 'vec',
            proof: 'proof',
            remediation: 'fix',
            confidence: 0.9,
        );
    }

    private function makeVulnerability(
        string $discriminator,
        VulnerabilitySeverity $vulnerabilitySeverity,
        VulnerabilityType $vulnerabilityType = VulnerabilityType::SQL_INJECTION,
    ): Vulnerability {
        return Vulnerability::create(
            vulnerabilityType: $vulnerabilityType,
            vulnerabilitySeverity: $vulnerabilitySeverity,
            title: 'Test '.$discriminator,
            description: 'Test vulnerability',
            filePath: 'src/'.$discriminator.'.php',
            lineStart: 1,
            lineEnd: 5,
            vulnerableCode: '$query',
            attackVector: 'Inject',
            proof: "' OR 1=1",
            remediation: 'Fix it',
            confidence: 0.9,
        );
    }
}
