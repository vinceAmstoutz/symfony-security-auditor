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

use Composer\InstalledVersions;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRenderer;

final class ReportRendererTest extends TestCase
{
    private ReportRenderer $reportRenderer;

    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/renderer_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
        $this->reportRenderer = new ReportRenderer();
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    public function test_render_console_no_vulns_has_two_double_bar_separators(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport());

        self::assertSame(2, substr_count($output, str_repeat('═', 70)));
        self::assertStringNotContainsString(str_repeat('═', 71), $output);
        self::assertStringNotContainsString("\n".str_repeat('═', 69)."\n", $output);
    }

    public function test_render_console_header_includes_package_name(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport());

        self::assertStringContainsString(ReportRenderer::PACKAGE_NAME, $output);
    }

    public function test_render_console_vulnerability_has_description_label_with_blank_line_above(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("\n\n  Description:\n", $output);
    }

    public function test_render_console_vulnerability_has_attack_vector_label_with_blank_line_above(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("\n\n  Attack Vector:\n", $output);
    }

    public function test_render_console_vulnerability_has_remediation_label_with_blank_line_above(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("\n\n  Remediation:\n", $output);
    }

    public function test_render_console_package_name_is_inside_double_bar_frame(): void
    {
        // Ensure the package line sits between the two `═` frame separators (right under the title),
        // not somewhere else in the body.
        $output = $this->reportRenderer->renderConsole($this->makeReport());
        $frame = str_repeat('═', 70);
        $firstFrame = strpos($output, $frame);
        $secondFrame = strpos($output, $frame, ($firstFrame ?: 0) + 1);
        $packagePosition = strpos($output, ReportRenderer::PACKAGE_NAME);

        self::assertNotFalse($firstFrame);
        self::assertNotFalse($secondFrame);
        self::assertNotFalse($packagePosition);
        self::assertGreaterThan($firstFrame, $packagePosition);
        self::assertLessThan($secondFrame, $packagePosition);
    }

    public function test_render_console_no_vulns_has_two_single_bar_separators(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport());

        self::assertSame(2, substr_count($output, str_repeat('─', 70)));
        self::assertStringNotContainsString(str_repeat('─', 71), $output);
        self::assertStringNotContainsString("\n".str_repeat('─', 69)."\n", $output);
    }

    public function test_render_console_with_vulns_has_four_single_bar_separators(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport($this->makeValidatedVuln()));

        self::assertSame(4, substr_count($output, str_repeat('─', 70)));
        self::assertStringNotContainsString(str_repeat('─', 71), $output);
    }

    public function test_render_console_vulnerability_dot_separator_is_exactly_70_chars(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString("\n".str_repeat('·', 70), $output);
        self::assertStringNotContainsString("\n".str_repeat('·', 71), $output);
        self::assertStringNotContainsString("\n".str_repeat('·', 69)."\n", $output);
    }

    public function test_render_console_with_zero_vulnerabilities_shows_no_findings_message(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport());

        self::assertStringContainsString('No validated vulnerabilities found.', $output);
        self::assertStringNotContainsString('VULNERABILITIES', $output);
    }

    public function test_render_console_lists_vulnerabilities_most_severe_first(): void
    {
        $vulnerability = $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::LOW, filePath: 'src/Low.php');
        $critical = $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::CRITICAL, filePath: 'src/Critical.php');

        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability, $critical));

        $criticalPosition = strpos($output, 'src/Critical.php');
        $lowPosition = strpos($output, 'src/Low.php');
        self::assertNotFalse($criticalPosition);
        self::assertNotFalse($lowPosition);
        self::assertLessThan($lowPosition, $criticalPosition);
    }

    public function test_render_console_with_vulnerabilities_skips_no_findings_message(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport($this->makeValidatedVuln()));

        self::assertStringNotContainsString('No validated vulnerabilities found.', $output);
        self::assertStringContainsString('VULNERABILITIES', $output);
    }

    public function test_render_console_severity_summary_shows_severity_with_count_one(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('HIGH', $output);
    }

    public function test_render_console_findings_output_ends_with_dot_separator_no_trailing_newline(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport($this->makeValidatedVuln()));

        self::assertStringEndsWith(str_repeat('·', 70), $output);
    }

    public function test_render_console_severity_summary_has_header_line(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('  SUMMARY BY SEVERITY', $output);
    }

    public function test_render_console_severity_summary_omits_zero_count_severities(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringNotContainsString('CRITICAL', $output);
    }

    public function test_render_json_returns_valid_json_array(): void
    {
        $decoded = json_decode($this->reportRenderer->renderJson($this->makeReport()), true);

        self::assertIsArray($decoded);
        self::assertArrayHasKey('audit_id', $decoded);
        self::assertArrayHasKey('vulnerabilities', $decoded);
    }

    public function test_render_sarif_has_required_top_level_keys(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertArrayHasKey('$schema', $decoded);
        self::assertArrayHasKey('version', $decoded);
        self::assertArrayHasKey('runs', $decoded);
    }

    public function test_render_sarif_version_is_2_1_0(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertSame('2.1.0', $decoded['version']);
    }

    public function test_render_sarif_driver_name_is_symfony_security_auditor(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertSame('Symfony Security Auditor', $decoded['runs'][0]['tool']['driver']['name']);
    }

    public function test_render_sarif_driver_version_matches_installed_package_version(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());
        $expected = InstalledVersions::getPrettyVersion(ReportRenderer::PACKAGE_NAME) ?? ReportRenderer::UNKNOWN_VERSION;

        self::assertSame($expected, $decoded['runs'][0]['tool']['driver']['version']);
    }

    public function test_render_sarif_driver_version_is_non_empty(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertNotSame('', $decoded['runs'][0]['tool']['driver']['version']);
    }

    public function test_render_sarif_runs_contains_tool_and_results_keys(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertArrayHasKey('tool', $decoded['runs'][0]);
        self::assertArrayHasKey('results', $decoded['runs'][0]);
    }

    public function test_render_sarif_rules_is_sequential_array_not_object(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        self::assertCount(1, $rules);
        self::assertSame(array_values($rules), $rules);
    }

    public function test_render_sarif_two_different_types_produce_two_rules(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::MEDIUM, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        self::assertCount(2, $rules);
    }

    public function test_render_sarif_results_contains_one_entry_per_vulnerability(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        self::assertCount(2, $decoded['runs'][0]['results']);
    }

    public function test_render_sarif_level_is_error_for_critical(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('error', $decoded['runs'][0]['results'][0]['level']);
    }

    public function test_render_sarif_level_is_error_for_high(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('error', $decoded['runs'][0]['results'][0]['level']);
    }

    public function test_render_sarif_level_is_warning_for_medium(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::MEDIUM);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('warning', $decoded['runs'][0]['results'][0]['level']);
    }

    public function test_render_sarif_level_is_note_for_low(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::LOW);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('note', $decoded['runs'][0]['results'][0]['level']);
    }

    public function test_render_sarif_level_is_note_for_info(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::INFO);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('note', $decoded['runs'][0]['results'][0]['level']);
    }

    public function test_render_sarif_result_location_contains_file_and_lines(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        $location = $decoded['runs'][0]['results'][0]['locations'][0]['physicalLocation'];
        self::assertArrayHasKey('artifactLocation', $location);
        self::assertArrayHasKey('region', $location);
        self::assertSame(1, $location['region']['startLine']);
        self::assertSame(5, $location['region']['endLine']);
    }

    public function test_render_sarif_produces_valid_unescaped_slashes_json(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());
        $schema = $decoded['$schema'];

        self::assertStringContainsString('/', (string) $schema);
        self::assertStringNotContainsString('\/', (string) $schema);
    }

    public function test_render_sarif_result_message_text_is_vulnerability_title(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('Test Vuln', $decoded['runs'][0]['results'][0]['message']['text']);
    }

    public function test_render_sarif_result_ruleid_is_owasp_reference(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame(VulnerabilityType::SQL_INJECTION->owaspReference(), $decoded['runs'][0]['results'][0]['ruleId']);
    }

    public function test_render_sarif_artifact_location_uri_is_vulnerability_file_path(): void
    {
        $vulnerability = $this->makeValidatedVuln(filePath: 'src/Foo.php');
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('src/Foo.php', $decoded['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']);
    }

    public function test_render_sarif_rule_short_description_text_is_type_category(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        $firstRule = array_values($rules)[0];
        self::assertArrayHasKey('shortDescription', $firstRule);
        self::assertIsArray($firstRule['shortDescription']);
        self::assertArrayHasKey('text', $firstRule['shortDescription']);
        self::assertSame(VulnerabilityType::SQL_INJECTION->category(), $firstRule['shortDescription']['text']);
    }

    public function test_render_sarif_rule_has_all_required_keys(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        $firstRule = array_values($rules)[0];
        self::assertSame(VulnerabilityType::SQL_INJECTION->owaspReference(), $firstRule['id']);
        self::assertSame(VulnerabilityType::SQL_INJECTION->value, $firstRule['name']);
        self::assertSame('https://owasp.org/Top10/', $firstRule['helpUri']);
    }

    public function test_render_sarif_rule_is_not_overwritten_when_same_type_appears_twice(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        self::assertCount(1, $rules);
        $firstRule = array_values($rules)[0];
        self::assertSame(VulnerabilityType::SQL_INJECTION->owaspReference(), $firstRule['id']);
        self::assertSame(VulnerabilityType::SQL_INJECTION->value, $firstRule['name']);
        self::assertIsArray($firstRule['shortDescription']);
        self::assertSame(VulnerabilityType::SQL_INJECTION->category(), $firstRule['shortDescription']['text']);
    }

    public function test_render_console_description_chunks_at_exactly_65_chars(): void
    {
        $longDescription = str_repeat('a', 70);
        $vulnerability = Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'Test Vuln',
            description: $longDescription,
            filePath: 'src/Foo.php',
            lineStart: 1,
            lineEnd: 5,
            vulnerableCode: '$q',
            attackVector: 'short',
            proof: 'p',
            remediation: 'r',
            confidence: 0.7,
        )->withReviewerValidation(true);

        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.str_repeat('a', 65)."\n    ".str_repeat('a', 5), $output);
    }

    public function test_render_console_attack_vector_chunks_at_exactly_65_chars(): void
    {
        $longVector = str_repeat('b', 70);
        $vulnerability = Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'Test Vuln',
            description: 'short',
            filePath: 'src/Foo.php',
            lineStart: 1,
            lineEnd: 5,
            vulnerableCode: '$q',
            attackVector: $longVector,
            proof: 'p',
            remediation: 'r',
            confidence: 0.7,
        )->withReviewerValidation(true);

        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.str_repeat('b', 65)."\n    ".str_repeat('b', 5), $output);
    }

    public function test_render_console_remediation_chunks_at_exactly_65_chars(): void
    {
        $longRemediation = str_repeat('c', 70);
        $vulnerability = Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'Test Vuln',
            description: 'short',
            filePath: 'src/Foo.php',
            lineStart: 1,
            lineEnd: 5,
            vulnerableCode: '$q',
            attackVector: 'short',
            proof: 'p',
            remediation: $longRemediation,
            confidence: 0.7,
        )->withReviewerValidation(true);

        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.str_repeat('c', 65)."\n    ".str_repeat('c', 5), $output);
    }

    public function test_render_console_substitutes_audit_id(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->reportRenderer->renderConsole($auditReport);

        self::assertStringContainsString($auditReport->auditId(), $output);
        self::assertStringNotContainsString('{{auditId}}', $output);
    }

    public function test_render_console_substitutes_project_path(): void
    {
        $output = $this->reportRenderer->renderConsole($this->makeReport());

        self::assertStringContainsString($this->tmpDir, $output);
        self::assertStringNotContainsString('{{projectPath}}', $output);
    }

    public function test_render_console_substitutes_started_at_in_iso_like_format(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->reportRenderer->renderConsole($auditReport);

        self::assertStringContainsString($auditReport->startedAt()->format('Y-m-d H:i:s'), $output);
        self::assertStringNotContainsString('{{startedAt}}', $output);
    }

    public function test_render_console_substitutes_duration_in_seconds(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->reportRenderer->renderConsole($auditReport);

        self::assertStringContainsString(\sprintf('%.1fs', $auditReport->durationSeconds()), $output);
        self::assertStringNotContainsString('{{duration}}', $output);
    }

    public function test_render_console_substitutes_files_scanned_count(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->reportRenderer->renderConsole($auditReport);

        self::assertStringContainsString(\sprintf('%d scanned', $auditReport->filesScanned()), $output);
        self::assertStringNotContainsString('{{filesScanned}}', $output);
    }

    public function test_render_console_substitutes_risk_level(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->reportRenderer->renderConsole($auditReport);

        self::assertStringContainsString($auditReport->riskLevel(), $output);
        self::assertStringNotContainsString('{{riskLevel}}', $output);
    }

    public function test_render_console_substitutes_risk_score(): void
    {
        $auditReport = $this->makeReport();
        $output = $this->reportRenderer->renderConsole($auditReport);

        self::assertStringContainsString(\sprintf('(Score: %d)', $auditReport->riskScore()), $output);
        self::assertStringNotContainsString('{{riskScore}}', $output);
    }

    public function test_render_console_substitutes_unknown_model_label_when_primary_model_is_empty(): void
    {
        $auditReport = $this->makeReportWithCost(AuditCost::zero(''));
        $output = $this->reportRenderer->renderConsole($auditReport);

        self::assertStringContainsString('unknown model', $output);
        self::assertStringNotContainsString('{{primaryModel}}', $output);
    }

    public function test_render_console_renders_cost_without_estimated_suffix(): void
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
        $output = $this->reportRenderer->renderConsole($auditReport);

        self::assertStringNotContainsString('Cost', $output);
        self::assertStringNotContainsString('$0.3755', $output);
        self::assertStringNotContainsString('$0.0350', $output);
        self::assertStringNotContainsString('$0.0050', $output);
        self::assertStringNotContainsString('{{cost}}', $output);
        self::assertStringNotContainsString('{{costBreakdown}}', $output);
        self::assertStringContainsString('100 in / 50 out (claude-opus-4-7)', $output);
    }

    public function test_render_console_substitutes_actual_model_name_when_primary_model_is_set(): void
    {
        $auditReport = $this->makeReportWithCost(AuditCost::of(100, 50, 0.05, 'claude-opus-4-7'));
        $output = $this->reportRenderer->renderConsole($auditReport);

        self::assertStringContainsString('claude-opus-4-7', $output);
        self::assertStringNotContainsString('unknown model', $output);
        self::assertStringNotContainsString('{{primaryModel}}', $output);
    }

    public function test_render_sarif_properties_block_includes_all_cost_keys_with_exact_values(): void
    {
        $auditReport = $this->makeReportWithCost(AuditCost::of(1234, 567, 1.2345, 'gpt-4o'));
        $decoded = $this->decodeSarifProperties($auditReport);

        self::assertSame(1234, $decoded['input_tokens']);
        self::assertSame(567, $decoded['output_tokens']);
        self::assertSame(1801, $decoded['total_tokens']);
        self::assertSame(1.2345, $decoded['estimated_cost_usd']);
        self::assertSame('gpt-4o', $decoded['primary_model']);
    }

    public function test_render_console_vulnerability_substitutes_id(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('['.$vulnerability->id().']', $output);
        self::assertStringNotContainsString('{{id}}', $output);
    }

    public function test_render_console_vulnerability_substitutes_title(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString($vulnerability->title(), $output);
        self::assertStringNotContainsString('{{title}}', $output);
    }

    public function test_render_console_vulnerability_substitutes_severity_label(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString(VulnerabilitySeverity::HIGH->label(), $output);
        self::assertStringNotContainsString('{{severity}}', $output);
    }

    public function test_render_console_vulnerability_substitutes_owasp_reference(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('OWASP: '.$vulnerability->type()->owaspReference(), $output);
        self::assertStringNotContainsString('{{owasp}}', $output);
    }

    public function test_render_console_vulnerability_substitutes_file_location_with_line_range(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString(\sprintf('File : %s:%d-%d', $vulnerability->filePath(), $vulnerability->lineStart(), $vulnerability->lineEnd()), $output);
        self::assertStringNotContainsString('{{filePath}}', $output);
        self::assertStringNotContainsString('{{lineStart}}', $output);
        self::assertStringNotContainsString('{{lineEnd}}', $output);
    }

    public function test_render_console_vulnerability_substitutes_description(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.$vulnerability->description(), $output);
        self::assertStringNotContainsString('{{description}}', $output);
    }

    public function test_render_console_vulnerability_substitutes_attack_vector(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.$vulnerability->attackVector(), $output);
        self::assertStringNotContainsString('{{attackVector}}', $output);
    }

    public function test_render_console_vulnerability_substitutes_proof(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.$vulnerability->proof(), $output);
        self::assertStringNotContainsString('{{proof}}', $output);
    }

    public function test_render_console_vulnerability_substitutes_remediation(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('    '.$vulnerability->remediation(), $output);
        self::assertStringNotContainsString('{{remediation}}', $output);
    }

    public function test_render_console_confidence_renders_as_exact_percent_value(): void
    {
        $vulnerability = Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: 'Test Vuln',
            description: 'short',
            filePath: 'src/Foo.php',
            lineStart: 1,
            lineEnd: 5,
            vulnerableCode: '$q',
            attackVector: 'short',
            proof: 'p',
            remediation: 'r',
            confidence: 0.7,
        )->withReviewerValidation(true);

        $output = $this->reportRenderer->renderConsole($this->makeReport($vulnerability));

        self::assertStringContainsString('Confidence: 70%', $output);
        self::assertStringNotContainsString('Confidence: 71%', $output);
        self::assertStringNotContainsString('Confidence: 69%', $output);
        self::assertStringNotContainsString('Confidence: 0%', $output);
    }

    /** @return array{input_tokens: int, output_tokens: int, total_tokens: int, estimated_cost_usd: float, primary_model: string} */
    private function decodeSarifProperties(AuditReport $auditReport): array
    {
        $decoded = $this->decodeSarif($auditReport);
        $properties = $decoded['runs'][0]['properties'] ?? null;
        $this->assertSarifPropertiesShape($properties);

        return $properties;
    }

    /**
     * @phpstan-assert array{input_tokens: int, output_tokens: int, total_tokens: int, estimated_cost_usd: float, primary_model: string} $value
     */
    private function assertSarifPropertiesShape(mixed $value): void
    {
        self::assertIsArray($value);
        self::assertArrayHasKey('input_tokens', $value);
        self::assertArrayHasKey('output_tokens', $value);
        self::assertArrayHasKey('total_tokens', $value);
        self::assertArrayHasKey('estimated_cost_usd', $value);
        self::assertArrayHasKey('primary_model', $value);
    }

    /**
     * @return array{
     *     "$schema": string,
     *     version: string,
     *     runs: list<array{
     *         tool: array{driver: array{name: string, version: string, informationUri: string, rules: array<int|string, array<string, mixed>>}},
     *         results: list<array{ruleId: string, level: string, message: array{text: string}, locations: list<array{physicalLocation: array{artifactLocation: array{uri: string}, region: array{startLine: int, endLine: int}}}>}>,
     *         properties?: array<string, mixed>
     *     }>
     * }
     */
    private function decodeSarif(AuditReport $auditReport): array
    {
        $decoded = json_decode($this->reportRenderer->renderSarif($auditReport), true);
        $this->assertSarifShape($decoded);

        return $decoded;
    }

    /**
     * @phpstan-assert array{
     *     "$schema": string,
     *     version: string,
     *     runs: list<array{
     *         tool: array{driver: array{name: string, version: string, informationUri: string, rules: array<int|string, array<string, mixed>>}},
     *         results: list<array{ruleId: string, level: string, message: array{text: string}, locations: list<array{physicalLocation: array{artifactLocation: array{uri: string}, region: array{startLine: int, endLine: int}}}>}>
     *     }>
     * } $value
     */
    private function assertSarifShape(mixed $value): void
    {
        self::assertIsArray($value);
    }

    public function test_render_html_is_a_complete_document(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReport());

        self::assertStringContainsString('<!doctype html>', $output);
        self::assertStringContainsString('</html>', $output);
    }

    public function test_render_html_shows_safe_message_when_no_vulnerabilities(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReport());

        self::assertStringContainsString('No validated vulnerabilities found.', $output);
        self::assertStringNotContainsString('<h2>Vulnerabilities', $output);
    }

    public function test_render_html_renders_risk_level_with_its_lowercased_css_class(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReport());

        self::assertStringContainsString('class="risk risk-safe"', $output);
        self::assertStringContainsString('>SAFE</span>', $output);
    }

    public function test_render_html_shows_the_primary_model(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReportWithCost(AuditCost::zero('claude-test-model')));

        self::assertStringContainsString('claude-test-model', $output);
        self::assertStringNotContainsString('unknown model', $output);
    }

    public function test_render_html_shows_unknown_model_when_the_primary_model_is_blank(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReportWithCost(AuditCost::zero('')));

        self::assertStringContainsString('unknown model', $output);
    }

    public function test_render_html_lists_a_validated_vulnerability(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReport($this->makeValidatedVuln(filePath: 'src/Admin/UserController.php')));

        self::assertStringContainsString('<h2>Vulnerabilities (1 total)</h2>', $output);
        self::assertStringContainsString('src/Admin/UserController.php', $output);
        self::assertStringContainsString('class="finding severity-high"', $output);
    }

    public function test_render_html_summary_counts_only_present_severities(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReport($this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::HIGH)));

        self::assertStringContainsString('<tr class="severity-high">', $output);
        self::assertStringContainsString('<td>1</td></tr>', $output);
        self::assertStringNotContainsString('<tr class="severity-critical">', $output);
    }

    public function test_render_html_escapes_finding_content_to_prevent_report_xss(): void
    {
        $vulnerability = Vulnerability::create(
            vulnerabilityType: VulnerabilityType::SQL_INJECTION,
            vulnerabilitySeverity: VulnerabilitySeverity::HIGH,
            title: '<script>alert(1)</script>',
            description: 'desc',
            filePath: 'src/Foo.php',
            lineStart: 1,
            lineEnd: 2,
            vulnerableCode: 'code',
            attackVector: 'vec',
            proof: 'proof',
            remediation: 'fix',
            confidence: 0.9,
        )->withReviewerValidation(true);

        $output = $this->reportRenderer->renderHtml($this->makeReport($vulnerability));

        self::assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $output);
        self::assertStringNotContainsString('<script>alert(1)</script>', $output);
    }

    public function test_render_html_renders_confidence_as_a_percentage(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString('90%', $output);
    }

    public function test_render_html_replaces_every_template_placeholder(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReport($this->makeValidatedVuln()));

        self::assertStringNotContainsString('{{', $output);
    }

    public function test_render_html_escapes_quote_characters_in_finding_fields(): void
    {
        // makeValidatedVuln's proof is "' OR 1=1"; the single quote must be
        // entity-encoded — `htmlspecialchars` with ENT_QUOTES, not without.
        $output = $this->reportRenderer->renderHtml($this->makeReport($this->makeValidatedVuln()));

        self::assertStringContainsString('&#039; OR 1=1', $output);
        self::assertStringNotContainsString("<pre>' OR 1=1", $output);
    }

    public function test_render_html_renders_the_location_with_file_and_line_range(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReport(
            $this->makeValidatedVuln(filePath: 'src/Repo.php', lineStart: 10),
        ));

        self::assertStringContainsString('<dd>src/Repo.php:10-14</dd>', $output);
    }

    public function test_render_html_summary_table_renders_exactly_one_row_per_present_severity(): void
    {
        $output = $this->reportRenderer->renderHtml($this->makeReport(
            $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::HIGH),
        ));

        $expectedTable = '<table class="summary"><caption>Summary by severity</caption>'
            .'<tr class="severity-high"><th>'.VulnerabilitySeverity::HIGH->label().'</th><td>1</td></tr>'
            .'</table>';

        self::assertStringContainsString($expectedTable, $output);
    }

    private function makeReport(Vulnerability ...$vulnerabilities): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        foreach ($vulnerabilities as $vulnerability) {
            $auditContext->addVulnerability($vulnerability);
        }

        return AuditReport::fromContext($auditContext);
    }

    private function makeReportWithCost(AuditCost $auditCost, Vulnerability ...$vulnerabilities): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        foreach ($vulnerabilities as $vulnerability) {
            $auditContext->addVulnerability($vulnerability);
        }

        return AuditReport::fromContext($auditContext, $auditCost);
    }

    private function makeValidatedVuln(
        VulnerabilityType $vulnerabilityType = VulnerabilityType::SQL_INJECTION,
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
        string $filePath = 'src/Foo.php',
        int $lineStart = 1,
    ): Vulnerability {
        return Vulnerability::create(
            vulnerabilityType: $vulnerabilityType,
            vulnerabilitySeverity: $vulnerabilitySeverity,
            title: 'Test Vuln',
            description: 'Test description',
            filePath: $filePath,
            lineStart: $lineStart,
            lineEnd: $lineStart + 4,
            vulnerableCode: '$q',
            attackVector: 'inject',
            proof: "' OR 1=1",
            remediation: 'fix',
            confidence: 0.9,
        )->withReviewerValidation(true);
    }
}
