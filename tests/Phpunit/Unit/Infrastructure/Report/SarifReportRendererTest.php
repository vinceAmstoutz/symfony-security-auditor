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
use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\BaselineSuppressingReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;

final class SarifReportRendererTest extends AbstractReportRendererTestCase
{
    #[Override]
    protected function createRenderer(): ReportRendererInterface
    {
        return new SarifReportRenderer();
    }

    public function test_it_advertises_the_sarif_format(): void
    {
        self::assertSame('sarif', $this->renderer->format());
    }

    public function test_render_has_required_top_level_keys(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertSame('https://json.schemastore.org/sarif-2.1.0.json', $decoded['$schema']);
        self::assertSame('2.1.0', $decoded['version']);
        self::assertCount(1, $decoded['runs']);
    }

    public function test_render_version_is_2_1_0(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertSame('2.1.0', $decoded['version']);
    }

    public function test_render_driver_name_is_symfony_security_auditor(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertSame('Symfony Security Auditor', $decoded['runs'][0]['tool']['driver']['name']);
    }

    public function test_render_driver_information_uri_is_the_project_homepage(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertSame('https://github.com/vinceamstoutz/symfony-security-auditor', $decoded['runs'][0]['tool']['driver']['informationUri']);
    }

    public function test_render_driver_version_matches_installed_package_version(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());
        $expected = InstalledVersions::getPrettyVersion(ReportPackage::NAME) ?? ReportPackage::UNKNOWN_VERSION;

        self::assertSame($expected, $decoded['runs'][0]['tool']['driver']['version']);
    }

    public function test_render_driver_version_is_non_empty(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertNotSame('', $decoded['runs'][0]['tool']['driver']['version']);
    }

    public function test_render_runs_contains_tool_and_results_keys(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());

        self::assertSame('Symfony Security Auditor', $decoded['runs'][0]['tool']['driver']['name']);
        self::assertArrayHasKey('results', $decoded['runs'][0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_rules_is_sequential_array_not_object(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        self::assertCount(1, $rules);
        self::assertSame(array_values($rules), $rules);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_two_different_types_produce_two_rules(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::MEDIUM, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        self::assertCount(2, $rules);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_a_rule_shared_by_two_types_carries_both_cwe_tags(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::COMMAND_INJECTION, VulnerabilitySeverity::CRITICAL, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        self::assertCount(1, $rules);
        self::assertSame(['external/cwe/cwe-78', 'external/cwe/cwe-89'], array_values($rules)[0]['properties']['tags']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_a_rule_does_not_repeat_the_cwe_tag_of_a_recurring_type(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        self::assertSame(['external/cwe/cwe-89'], array_values($rules)[0]['properties']['tags']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_results_contains_one_entry_per_vulnerability(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        self::assertCount(2, $decoded['runs'][0]['results']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_level_is_error_for_critical(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('error', $decoded['runs'][0]['results'][0]['level']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_level_is_error_for_high(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('error', $decoded['runs'][0]['results'][0]['level']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_level_is_warning_for_medium(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::MEDIUM);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('warning', $decoded['runs'][0]['results'][0]['level']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_level_is_note_for_low(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::LOW);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('note', $decoded['runs'][0]['results'][0]['level']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_level_is_note_for_info(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::INFO);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('note', $decoded['runs'][0]['results'][0]['level']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_result_location_contains_file_and_lines(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        $location = $decoded['runs'][0]['results'][0]['locations'][0]['physicalLocation'];
        self::assertSame('src/Foo.php', $location['artifactLocation']['uri']);
        self::assertSame(1, $location['region']['startLine']);
        self::assertSame(5, $location['region']['endLine']);
    }

    public function test_render_produces_valid_unescaped_slashes_json(): void
    {
        $decoded = $this->decodeSarif($this->makeReport());
        $schema = $decoded['$schema'];

        self::assertStringContainsString('/', $schema);
        self::assertStringNotContainsString('\/', $schema);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_result_message_text_is_vulnerability_title(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('Test Vuln', $decoded['runs'][0]['results'][0]['message']['text']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_result_ruleid_is_owasp_reference(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame(VulnerabilityType::SQL_INJECTION->owaspReference(), $decoded['runs'][0]['results'][0]['ruleId']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_artifact_location_uri_is_vulnerability_file_path(): void
    {
        $vulnerability = $this->makeValidatedVuln(filePath: 'src/Foo.php');
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame('src/Foo.php', $decoded['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_rule_short_description_text_is_type_category(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        $firstRule = array_values($rules)[0];
        self::assertSame(VulnerabilityType::SQL_INJECTION->category(), $firstRule['shortDescription']['text']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_rule_has_all_required_keys(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        $firstRule = array_values($rules)[0];
        self::assertSame(VulnerabilityType::SQL_INJECTION->owaspReference(), $firstRule['id']);
        self::assertSame(VulnerabilityType::SQL_INJECTION->value, $firstRule['name']);
        self::assertSame(VulnerabilityType::SQL_INJECTION->owaspReferenceUrl(), $firstRule['helpUri']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_rule_help_uri_points_to_the_specific_owasp_category(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        $firstRule = array_values($decoded['runs'][0]['tool']['driver']['rules'])[0];
        self::assertSame('https://owasp.org/Top10/2025/A05_2025-Injection/', $firstRule['helpUri']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_rule_properties_tags_include_the_cwe_reference(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        $firstRule = array_values($decoded['runs'][0]['tool']['driver']['rules'])[0];
        self::assertSame(['external/cwe/cwe-89'], $firstRule['properties']['tags']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_result_carries_the_vulnerability_partial_fingerprint(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertSame(
            $vulnerability->fingerprint(),
            $decoded['runs'][0]['results'][0]['partialFingerprints']['symfonySecurityAuditor/v1'],
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_result_has_no_suppressions_by_default(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $decoded = $this->decodeSarif($this->makeReport($vulnerability));

        self::assertArrayNotHasKey('suppressions', $decoded['runs'][0]['results'][0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_with_suppressions_marks_the_baselined_finding_as_externally_suppressed(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $decoded = $this->decodeSarifWithSuppressions($this->makeReport($vulnerability), [$vulnerability->fingerprint()]);

        self::assertSame(
            [['kind' => 'external', 'justification' => 'Accepted via audit baseline']],
            $decoded['runs'][0]['results'][0]['suppressions'] ?? null,
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_with_suppressions_leaves_a_non_baselined_finding_unsuppressed(): void
    {
        $vulnerability = $this->makeValidatedVuln();
        $decoded = $this->decodeSarifWithSuppressions($this->makeReport($vulnerability), ['SSA-UNRELATED']);

        self::assertArrayNotHasKey('suppressions', $decoded['runs'][0]['results'][0]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_render_rule_is_not_overwritten_when_same_type_appears_twice(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'src/Bar.php', 10);
        $decoded = $this->decodeSarif($this->makeReport($vulnerability, $vuln2));

        $rules = $decoded['runs'][0]['tool']['driver']['rules'];
        self::assertCount(1, $rules);
        $firstRule = array_values($rules)[0];
        self::assertSame(VulnerabilityType::SQL_INJECTION->owaspReference(), $firstRule['id']);
        self::assertSame(VulnerabilityType::SQL_INJECTION->value, $firstRule['name']);
        self::assertSame(VulnerabilityType::SQL_INJECTION->category(), $firstRule['shortDescription']['text']);
    }

    public function test_render_properties_block_includes_all_cost_keys_with_exact_values(): void
    {
        $auditReport = $this->makeReportWithCost(AuditCost::of(1234, 567, 1.2345, 'gpt-4o'));
        $decoded = $this->decodeSarifProperties($auditReport);

        self::assertSame(1234, $decoded['input_tokens']);
        self::assertSame(567, $decoded['output_tokens']);
        self::assertSame(1801, $decoded['total_tokens']);
        self::assertSame(1.2345, $decoded['estimated_cost_usd']);
        self::assertSame('gpt-4o', $decoded['primary_model']);
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
     *         tool: array{driver: array{name: string, version: string, informationUri: string, rules: array<int|string, array{id: string, name: string, shortDescription: array{text: string}, helpUri: string, properties: array{tags: list<string>}}>}},
     *         results: list<array{ruleId: string, level: string, message: array{text: string}, partialFingerprints: array<string, string>, locations: list<array{physicalLocation: array{artifactLocation: array{uri: string}, region: array{startLine: int, endLine: int}}}>}>,
     *         properties?: array<string, mixed>
     *     }>
     * }
     */
    private function decodeSarif(AuditReport $auditReport): array
    {
        $decoded = json_decode($this->renderer->render($auditReport), true);
        $this->assertSarifShape($decoded);

        return $decoded;
    }

    /**
     * @param list<string> $baselinedFingerprints
     *
     * @return array{
     *     "$schema": string,
     *     version: string,
     *     runs: list<array{
     *         tool: array{driver: array{name: string, version: string, informationUri: string, rules: array<int|string, array<string, mixed>>}},
     *         results: list<array{ruleId: string, level: string, message: array{text: string}, partialFingerprints: array<string, string>, locations: list<array{physicalLocation: array{artifactLocation: array{uri: string}, region: array{startLine: int, endLine: int}}}>, suppressions?: list<array{kind: string, justification: string}>}>,
     *         properties?: array<string, mixed>
     *     }>
     * }
     */
    private function decodeSarifWithSuppressions(AuditReport $auditReport, array $baselinedFingerprints): array
    {
        self::assertInstanceOf(BaselineSuppressingReportRendererInterface::class, $this->renderer);
        $decoded = json_decode($this->renderer->renderWithSuppressions($auditReport, $baselinedFingerprints), true);
        $this->assertSarifShape($decoded);

        return $decoded;
    }

    /**
     * @phpstan-assert array{
     *     "$schema": string,
     *     version: string,
     *     runs: list<array{
     *         tool: array{driver: array{name: string, version: string, informationUri: string, rules: array<int|string, array{id: string, name: string, shortDescription: array{text: string}, helpUri: string, properties: array{tags: list<string>}}>}},
     *         results: list<array{ruleId: string, level: string, message: array{text: string}, partialFingerprints: array<string, string>, locations: list<array{physicalLocation: array{artifactLocation: array{uri: string}, region: array{startLine: int, endLine: int}}}>}>
     *     }>
     * } $value
     */
    private function assertSarifShape(mixed $value): void
    {
        self::assertIsArray($value);
    }
}
