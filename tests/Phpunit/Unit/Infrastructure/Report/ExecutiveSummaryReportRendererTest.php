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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Report;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ExecutiveSummaryReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;

final class ExecutiveSummaryReportRendererTest extends AbstractReportRendererTestCase
{
    #[Override]
    protected function createRenderer(): ReportRendererInterface
    {
        return new ExecutiveSummaryReportRenderer();
    }

    public function test_it_advertises_the_executive_format(): void
    {
        self::assertSame('executive', $this->renderer->format());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_replaces_every_template_placeholder(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringNotContainsString('{{', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_clean_report_states_that_nothing_was_found(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString('No validated vulnerabilities found.', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_clean_report_reports_no_business_exposure(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString('this audit identified no business exposure', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('businessImpactCases')]
    public function test_it_frames_the_business_impact_of_the_reports_risk_level(int $criticalFindingCount, string $expectedFraming): void
    {
        $vulnerabilities = [];
        for ($index = 0; $index < $criticalFindingCount; ++$index) {
            $vulnerabilities[] = $this->makeValidatedVuln(
                vulnerabilitySeverity: VulnerabilitySeverity::CRITICAL,
                filePath: \sprintf('src/Finding%d.php', $index),
            );
        }

        $output = $this->renderer->render($this->makeReport(...$vulnerabilities));

        self::assertStringContainsString($expectedFraming, $output);
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function businessImpactCases(): iterable
    {
        yield 'critical at five findings (score 50)' => [5, 'Immediate action required'];
        yield 'high at three findings (score 30)' => [3, 'Action required this sprint'];
        yield 'medium at two findings (score 20)' => [2, 'Plan remediation'];
        yield 'low at one finding (score 10)' => [1, 'Low business exposure'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_counts_findings_and_the_files_they_touch(): void
    {
        $output = $this->renderer->render($this->makeReport(
            $this->makeValidatedVuln(filePath: 'src/One.php'),
            $this->makeValidatedVuln(filePath: 'src/Two.php'),
        ));

        self::assertStringContainsString('2 validated finding(s) across 2 file(s).', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_breaks_findings_down_by_severity(): void
    {
        $output = $this->renderer->render($this->makeReport(
            $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::HIGH),
        ));

        self::assertMatchesRegularExpression(
            '/BY SEVERITY\n\s+'.preg_quote(VulnerabilitySeverity::HIGH->label(), '/').'\s+1/',
            $output,
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_breaks_findings_down_by_type(): void
    {
        $output = $this->renderer->render($this->makeReport(
            $this->makeValidatedVuln(vulnerabilityType: VulnerabilityType::SQL_INJECTION),
        ));

        self::assertMatchesRegularExpression(
            '/BY TYPE\n\s+'.preg_quote(VulnerabilityType::SQL_INJECTION->value, '/').'\s+1/',
            $output,
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_lists_the_most_affected_files_first(): void
    {
        $output = $this->renderer->render($this->makeReport(
            $this->makeValidatedVuln(filePath: 'src/Quiet.php'),
            $this->makeValidatedVuln(filePath: 'src/Hotspot.php', lineStart: 10),
            $this->makeValidatedVuln(filePath: 'src/Hotspot.php', lineStart: 20),
        ));

        self::assertMatchesRegularExpression('/src\/Hotspot\.php\s+2.*src\/Quiet\.php\s+1/s', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_caps_the_hotspot_list_at_five_files(): void
    {
        $vulnerabilities = [];
        for ($index = 0; $index < 6; ++$index) {
            $vulnerabilities[] = $this->makeValidatedVuln(filePath: \sprintf('src/File%d.php', $index));
        }

        $output = $this->renderer->render($this->makeReport(...$vulnerabilities));

        self::assertStringContainsString('TOP AFFECTED FILES (of 6)', $output);
        self::assertSame(5, preg_match_all('/src\/File\d\.php/', $output));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_omits_the_per_finding_technical_detail(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringNotContainsString('Test description', $output);
        self::assertStringNotContainsString("' OR 1=1", $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_strips_terminal_control_sequences_from_a_reported_file_path(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Title', 0.9),
            new CodeLocation("src/\u{202E}Spoofed.php\r\n  FAKE LINE", 1, 2),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            'code',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringNotContainsString("\u{202E}", $output);
        self::assertStringNotContainsString("\r", $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_aligns_every_distribution_row_on_a_fixed_label_column(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString('  🟠 HIGH                                             1', $output);
        self::assertStringContainsString('  sql_injection                                      1', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_wraps_the_business_impact_prose_to_the_report_width(): void
    {
        $output = $this->renderer->render($this->makeReport(
            $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::CRITICAL, filePath: 'src/One.php'),
            $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::CRITICAL, filePath: 'src/Two.php'),
        ));

        self::assertStringContainsString(
            "Plan remediation: no single finding is decisive, but together they\n  weaken defence in depth and shorten the path to a breach.",
            $output,
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_reports_the_audited_duration_with_one_decimal(): void
    {
        $auditReport = $this->makeReport();

        $output = $this->renderer->render($auditReport);

        self::assertStringContainsString(
            \sprintf('(%d files, %ss)', $auditReport->filesScanned(), number_format($auditReport->durationSeconds(), 1, '.', '')),
            $output,
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_reports_the_risk_level_and_score(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString('RISK LEVEL: SAFE  (Score: 0)', $output);
    }
}
