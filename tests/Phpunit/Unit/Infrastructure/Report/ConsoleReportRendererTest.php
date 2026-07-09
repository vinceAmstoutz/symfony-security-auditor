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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ConsoleReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;

final class ConsoleReportRendererTest extends AbstractReportRendererTestCase
{
    #[Override]
    protected function createRenderer(): ReportRendererInterface
    {
        return new ConsoleReportRenderer();
    }

    public function test_it_advertises_the_console_format(): void
    {
        self::assertSame('console', $this->renderer->format());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_no_vulns_has_two_double_bar_separators(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertSame(2, substr_count($output, str_repeat('═', 70)));
        self::assertStringNotContainsString(str_repeat('═', 71), $output);
        self::assertStringNotContainsString("\n".str_repeat('═', 69)."\n", $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_header_includes_package_name(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString(ReportPackage::NAME, $output);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_substitutes_invalid_utf8_in_description_instead_of_throwing(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Title', 0.9),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative("Bad\xFFDescription", 'vec', 'proof', 'fix'),
            'code',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('Description', $output);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_substitutes_invalid_utf8_in_title_instead_of_corrupting_the_output(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, "Bad\xFFTitle", 0.9),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            'code',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertTrue(mb_check_encoding($output, 'UTF-8'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_has_description_label_with_blank_line_above(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("\n\n  Description:\n", $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_has_attack_vector_label_with_blank_line_above(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("\n\n  Attack Vector:\n", $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_has_remediation_label_with_blank_line_above(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("\n\n  Remediation:\n", $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_package_name_is_inside_double_bar_frame(): void
    {
        $output = $this->renderer->render($this->makeReport());
        $frame = str_repeat('═', 70);
        $firstFrame = strpos($output, $frame);
        $secondFrame = strpos($output, $frame, (false === $firstFrame ? 0 : $firstFrame) + 1);
        $packagePosition = strpos($output, ReportPackage::NAME);

        self::assertNotFalse($firstFrame);
        self::assertNotFalse($secondFrame);
        self::assertNotFalse($packagePosition);
        self::assertGreaterThan($firstFrame, $packagePosition);
        self::assertLessThan($secondFrame, $packagePosition);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_header_includes_the_project_homepage_url(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString('https://github.com/vinceamstoutz/symfony-security-auditor', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_homepage_url_is_inside_double_bar_frame(): void
    {
        $output = $this->renderer->render($this->makeReport());
        $frame = str_repeat('═', 70);
        $firstFrame = strpos($output, $frame);
        $secondFrame = strpos($output, $frame, (false === $firstFrame ? 0 : $firstFrame) + 1);
        $urlPosition = strpos($output, 'https://github.com/vinceamstoutz/symfony-security-auditor');

        self::assertNotFalse($firstFrame);
        self::assertNotFalse($secondFrame);
        self::assertNotFalse($urlPosition);
        self::assertGreaterThan($firstFrame, $urlPosition);
        self::assertLessThan($secondFrame, $urlPosition);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_no_vulns_has_two_single_bar_separators(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertSame(2, substr_count($output, str_repeat('─', 70)));
        self::assertStringNotContainsString(str_repeat('─', 71), $output);
        self::assertStringNotContainsString("\n".str_repeat('─', 69)."\n", $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_with_vulns_has_four_single_bar_separators(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertSame(4, substr_count($output, str_repeat('─', 70)));
        self::assertStringNotContainsString(str_repeat('─', 71), $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_dot_separator_is_exactly_70_chars(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("\n".str_repeat('·', 70), $output);
        self::assertStringNotContainsString("\n".str_repeat('·', 71), $output);
        self::assertStringNotContainsString("\n".str_repeat('·', 69)."\n", $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_with_zero_vulnerabilities_shows_no_findings_message(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString('No validated vulnerabilities found.', $output);
        self::assertStringNotContainsString('VULNERABILITIES', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_lists_vulnerabilities_most_severe_first(): void
    {
        $vulnerability = $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::LOW, filePath: 'src/Low.php');
        $critical = $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::CRITICAL, filePath: 'src/Critical.php');

        $output = $this->renderer->render($this->makeReport($vulnerability, $critical));

        $criticalPosition = strpos($output, 'src/Critical.php');
        $lowPosition = strpos($output, 'src/Low.php');
        self::assertNotFalse($criticalPosition);
        self::assertNotFalse($lowPosition);
        self::assertLessThan($lowPosition, $criticalPosition);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_with_vulnerabilities_skips_no_findings_message(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringNotContainsString('No validated vulnerabilities found.', $output);
        self::assertStringContainsString('VULNERABILITIES', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_severity_summary_shows_severity_with_count_one(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('HIGH', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_findings_output_ends_with_dot_separator_no_trailing_newline(): void
    {
        $output = $this->renderer->render($this->makeReport($this->makeValidatedVuln()));

        self::assertStringEndsWith(str_repeat('·', 70), $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_severity_summary_has_header_line(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('  SUMMARY BY SEVERITY', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_severity_summary_omits_zero_count_severities(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringNotContainsString('CRITICAL', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_description_chunks_at_exactly_65_chars(): void
    {
        $longDescription = str_repeat('a', 70);
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test Vuln', 0.7),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative($longDescription, 'short', 'p', 'r'),
            '$q',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.str_repeat('a', 65)."\n    ".str_repeat('a', 5), $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_wraps_multibyte_text_without_splitting_a_character(): void
    {
        $accentedDescription = str_repeat('é', 70);
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test Vuln', 0.7),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative($accentedDescription, 'short', 'p', 'r'),
            '$q',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertTrue(mb_check_encoding($output, 'UTF-8'));
        self::assertStringContainsString('    '.str_repeat('é', 65)."\n    ".str_repeat('é', 5), $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_attack_vector_chunks_at_exactly_65_chars(): void
    {
        $longVector = str_repeat('b', 70);
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test Vuln', 0.7),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative('short', $longVector, 'p', 'r'),
            '$q',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.str_repeat('b', 65)."\n    ".str_repeat('b', 5), $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_remediation_chunks_at_exactly_65_chars(): void
    {
        $longRemediation = str_repeat('c', 70);
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test Vuln', 0.7),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative('short', 'short', 'p', $longRemediation),
            '$q',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.str_repeat('c', 65)."\n    ".str_repeat('c', 5), $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_substitutes_audit_id(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->renderer->render($auditReport);

        self::assertStringContainsString($auditReport->auditId(), $output);
        self::assertStringNotContainsString('{{auditId}}', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_substitutes_project_path(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString($this->tmpDir, $output);
        self::assertStringNotContainsString('{{projectPath}}', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_substitutes_started_at_in_iso_like_format(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->renderer->render($auditReport);

        self::assertStringContainsString($auditReport->startedAt()->format('Y-m-d H:i:s'), $output);
        self::assertStringNotContainsString('{{startedAt}}', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_substitutes_duration_in_seconds(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->renderer->render($auditReport);

        self::assertStringContainsString(\sprintf('%.1fs', $auditReport->durationSeconds()), $output);
        self::assertStringNotContainsString('{{duration}}', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_formats_duration_with_a_period_regardless_of_the_process_numeric_locale(): void
    {
        $previousLocale = setlocale(\LC_NUMERIC, '0');
        setlocale(\LC_NUMERIC, 'de_DE.UTF-8');

        try {
            $auditReport = $this->makeReport();
            $output = $this->renderer->render($auditReport);
        } finally {
            setlocale(\LC_NUMERIC, false !== $previousLocale ? $previousLocale : 'C');
        }

        self::assertStringContainsString(number_format($auditReport->durationSeconds(), 1, '.', '').'s', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_substitutes_files_scanned_count(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->renderer->render($auditReport);

        self::assertStringContainsString(\sprintf('%d scanned', $auditReport->filesScanned()), $output);
        self::assertStringNotContainsString('{{filesScanned}}', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_substitutes_risk_level(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->renderer->render($auditReport);

        self::assertStringContainsString($auditReport->riskLevel(), $output);
        self::assertStringNotContainsString('{{riskLevel}}', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_substitutes_risk_score(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->renderer->render($auditReport);

        self::assertStringContainsString(\sprintf('(Score: %d)', $auditReport->riskScore()), $output);
        self::assertStringNotContainsString('{{riskScore}}', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_substitutes_unknown_model_label_when_primary_model_is_empty(): void
    {
        $auditReport = $this->makeReportWithCost(AuditCost::zero(''));
        $output = $this->renderer->render($auditReport);

        self::assertStringContainsString('unknown model', $output);
        self::assertStringNotContainsString('{{primaryModel}}', $output);
    }

    /**
     * @throws InvalidAuditCostException
     * @throws InvalidAuditContextException
     */
    public function test_render_renders_cost_without_estimated_suffix(): void
    {
        $auditReport = $this->makeReportWithCost(AuditCost::of(
            inputTokens: 100,
            outputTokens: 50,
            estimatedCostUsd: 0.3755,
            primaryModel: 'claude-opus-4-7',
            byRole: [
                'attacker' => ['model' => 'claude-opus-4-7', 'input_tokens' => 100, 'output_tokens' => 20, 'estimated_cost_usd' => 0.035],
                'reviewer' => ['model' => 'claude-haiku-4-5', 'input_tokens' => 50, 'output_tokens' => 10, 'estimated_cost_usd' => 0.005],
            ],
        ));
        $output = $this->renderer->render($auditReport);

        self::assertStringNotContainsString('Cost', $output);
        self::assertStringNotContainsString('$0.3755', $output);
        self::assertStringNotContainsString('$0.0350', $output);
        self::assertStringNotContainsString('$0.0050', $output);
        self::assertStringNotContainsString('{{cost}}', $output);
        self::assertStringNotContainsString('{{costBreakdown}}', $output);
        self::assertStringContainsString('100 in / 50 out (claude-opus-4-7)', $output);
    }

    /**
     * @throws InvalidAuditCostException
     * @throws InvalidAuditContextException
     */
    public function test_render_substitutes_actual_model_name_when_primary_model_is_set(): void
    {
        $auditReport = $this->makeReportWithCost(AuditCost::of(100, 50, 0.05, 'claude-opus-4-7'));
        $output = $this->renderer->render($auditReport);

        self::assertStringContainsString('claude-opus-4-7', $output);
        self::assertStringNotContainsString('unknown model', $output);
        self::assertStringNotContainsString('{{primaryModel}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_id(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('['.$vulnerability->id().']', $output);
        self::assertStringNotContainsString('{{id}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_title(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString($vulnerability->title(), $output);
        self::assertStringNotContainsString('{{title}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_strips_raw_ansi_escape_and_carriage_return_bytes_from_the_title_and_file_path(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, "Real SQLi\x1b[2K\rAll clear", 0.9),
            new CodeLocation("src/Foo\x1b[31m.php", 1, 5),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            '$q',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('Real SQLi', $output);
        self::assertStringContainsString('All clear', $output);
        self::assertStringContainsString('src/Foo', $output);
        self::assertStringContainsString('.php:1-5', $output);
        self::assertStringNotContainsString("\x1b", $output);
        self::assertStringNotContainsString("\r", $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_collapses_embedded_newlines_in_the_title_and_file_path_to_prevent_a_forged_finding_block(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::LOW, "Injected\n\n[FAKE-999] CRITICAL", 0.9),
            new CodeLocation("src/Foo.php\n\n[FAKE-999] CRITICAL", 1, 5),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            '$q',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringNotContainsString("\n[FAKE-999] CRITICAL", $output);
        self::assertStringContainsString('Injected', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_severity_label(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString(VulnerabilitySeverity::HIGH->label(), $output);
        self::assertStringNotContainsString('{{severity}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_owasp_reference(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('OWASP: '.$vulnerability->type()->owaspReference(), $output);
        self::assertStringNotContainsString('{{owasp}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_cwe_reference(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('CWE  : '.$vulnerability->type()->cwe()->label(), $output);
        self::assertStringNotContainsString('{{cwe}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_file_location_with_line_range(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString(\sprintf('File : %s:%d-%d', $vulnerability->filePath(), $vulnerability->lineStart(), $vulnerability->lineEnd()), $output);
        self::assertStringNotContainsString('{{filePath}}', $output);
        self::assertStringNotContainsString('{{lineStart}}', $output);
        self::assertStringNotContainsString('{{lineEnd}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_description(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.$vulnerability->description(), $output);
        self::assertStringNotContainsString('{{description}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_attack_vector(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.$vulnerability->attackVector(), $output);
        self::assertStringNotContainsString('{{attackVector}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_proof(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.$vulnerability->proof(), $output);
        self::assertStringNotContainsString('{{proof}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_includes_the_vulnerable_code(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('$q', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_includes_the_synthesized_poc_when_present(): void
    {
        $vulnerability = $this->makeValidatedVuln()->withSynthesizedPoC("curl -X POST https://victim.example/admin\n  -d 'id=1 OR 1=1'");
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString("    curl -X POST https://victim.example/admin\n      -d 'id=1 OR 1=1'", $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_omits_the_synthesized_poc_section_when_absent(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringNotContainsString('Synthesized PoC', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_indents_every_line_of_a_multi_line_proof(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test Vuln', 0.9),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative('desc', 'vec', "GET /admin/users HTTP/1.1\nHost: victim.example\nCookie: session=abc", 'fix'),
            "\$x = ' OR 1=1",
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString("    GET /admin/users HTTP/1.1\n    Host: victim.example\n    Cookie: session=abc", $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_vulnerability_substitutes_remediation(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.$vulnerability->remediation(), $output);
        self::assertStringNotContainsString('{{remediation}}', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_confidence_renders_as_exact_percent_value(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test Vuln', 0.7),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative('short', 'short', 'p', 'r'),
            '$q',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('Confidence: 70%', $output);
        self::assertStringNotContainsString('Confidence: 71%', $output);
        self::assertStringNotContainsString('Confidence: 69%', $output);
        self::assertStringNotContainsString('Confidence: 0%', $output);
    }
}
