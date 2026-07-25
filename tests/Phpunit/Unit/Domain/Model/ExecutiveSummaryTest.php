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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ExecutiveSummary;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class ExecutiveSummaryTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     */
    public function test_an_empty_report_summarizes_as_safe_with_no_findings(): void
    {
        $executiveSummary = ExecutiveSummary::of($this->report());

        self::assertSame(RiskLevel::Safe, $executiveSummary->riskLevel);
        self::assertSame(0, $executiveSummary->totalFindings);
        self::assertSame([], $executiveSummary->severityCounts);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_carries_the_reports_risk_score(): void
    {
        $auditReport = $this->report($this->vulnerability());

        self::assertSame($auditReport->riskScore(), ExecutiveSummary::of($auditReport)->riskScore);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_severity_counts_are_ordered_most_severe_first_and_omit_absent_severities(): void
    {
        $executiveSummary = ExecutiveSummary::of($this->report(
            $this->vulnerability(vulnerabilitySeverity: VulnerabilitySeverity::LOW),
            $this->vulnerability(vulnerabilitySeverity: VulnerabilitySeverity::CRITICAL, lineStart: 10),
            $this->vulnerability(vulnerabilitySeverity: VulnerabilitySeverity::LOW, lineStart: 20),
        ));

        self::assertSame(['critical' => 1, 'low' => 2], $executiveSummary->severityCounts);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_type_counts_are_ordered_most_frequent_first(): void
    {
        $executiveSummary = ExecutiveSummary::of($this->report(
            $this->vulnerability(vulnerabilityType: VulnerabilityType::TWIG_INJECTION),
            $this->vulnerability(vulnerabilityType: VulnerabilityType::SQL_INJECTION),
            $this->vulnerability(vulnerabilityType: VulnerabilityType::SQL_INJECTION, lineStart: 10),
        ));

        self::assertSame(
            [VulnerabilityType::SQL_INJECTION->value => 2, VulnerabilityType::TWIG_INJECTION->value => 1],
            $executiveSummary->typeCounts,
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_equally_frequent_types_are_ordered_alphabetically(): void
    {
        $executiveSummary = ExecutiveSummary::of($this->report(
            $this->vulnerability(vulnerabilityType: VulnerabilityType::TWIG_INJECTION),
            $this->vulnerability(vulnerabilityType: VulnerabilityType::SQL_INJECTION),
        ));

        self::assertSame(
            [VulnerabilityType::SQL_INJECTION->value, VulnerabilityType::TWIG_INJECTION->value],
            array_keys($executiveSummary->typeCounts),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_affected_files_are_counted_per_path_most_affected_first(): void
    {
        $executiveSummary = ExecutiveSummary::of($this->report(
            $this->vulnerability(filePath: 'src/Quiet.php'),
            $this->vulnerability(filePath: 'src/Hotspot.php', lineStart: 10),
            $this->vulnerability(filePath: 'src/Hotspot.php', lineStart: 20),
        ));

        self::assertSame(['src/Hotspot.php' => 2, 'src/Quiet.php' => 1], $executiveSummary->affectedFileCounts);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_affected_file_count_counts_distinct_files_not_findings(): void
    {
        $executiveSummary = ExecutiveSummary::of($this->report(
            $this->vulnerability(filePath: 'src/Hotspot.php', lineStart: 10),
            $this->vulnerability(filePath: 'src/Hotspot.php', lineStart: 20),
        ));

        self::assertSame(1, $executiveSummary->affectedFileCount());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_top_affected_files_keeps_the_most_affected_within_the_limit(): void
    {
        $executiveSummary = ExecutiveSummary::of($this->report(
            $this->vulnerability(filePath: 'src/Quiet.php'),
            $this->vulnerability(filePath: 'src/Hotspot.php', lineStart: 10),
            $this->vulnerability(filePath: 'src/Hotspot.php', lineStart: 20),
        ));

        self::assertSame(['src/Hotspot.php' => 2], $executiveSummary->topAffectedFiles(1));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_negative_top_affected_files_limit_yields_nothing(): void
    {
        $executiveSummary = ExecutiveSummary::of($this->report(
            $this->vulnerability(filePath: 'src/One.php'),
            $this->vulnerability(filePath: 'src/Two.php'),
        ));

        self::assertSame([], $executiveSummary->topAffectedFiles(-1));
    }

    /**
     * @throws InvalidAuditContextException
     */
    private function report(Vulnerability ...$vulnerabilities): AuditReport
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        foreach ($vulnerabilities as $vulnerability) {
            $auditContext->addVulnerability($vulnerability);
        }

        return AuditReport::fromContext($auditContext);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerability(
        VulnerabilityType $vulnerabilityType = VulnerabilityType::SQL_INJECTION,
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
        string $filePath = 'src/Foo.php',
        int $lineStart = 1,
    ): Vulnerability {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, $vulnerabilitySeverity, 'Test Vuln', 0.9),
            new CodeLocation($filePath, $lineStart, $lineStart + 4),
            new VulnerabilityNarrative('Test description', 'inject', 'proof', 'fix'),
            '$q',
        )->withReviewerValidation(true);
    }
}
