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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class AttackerContextPromptRendererTest extends TestCase
{
    /**
     * @throws InvalidRiskMarkerException
     */
    public function test_it_renders_each_marker_as_line_pattern_description(): void
    {
        $output = (new AttackerContextPromptRenderer())->renderRiskMarkers([
            RiskMarker::create('src/Controller/UserController.php', 42, 'request_get', 'Request input read'),
        ]);

        self::assertStringContainsString('L42 request_get — Request input read', $output);
    }

    /**
     * @throws InvalidRiskMarkerException
     */
    public function test_it_groups_markers_under_their_file_path(): void
    {
        $output = (new AttackerContextPromptRenderer())->renderRiskMarkers([
            RiskMarker::create('src/Controller/UserController.php', 42, 'request_get', 'A'),
            RiskMarker::create('src/Controller/UserController.php', 50, 'redirect_with_input', 'B'),
        ]);

        self::assertSame(1, substr_count($output, 'src/Controller/UserController.php:'));
        self::assertStringContainsString('L42 request_get — A', $output);
        self::assertStringContainsString('L50 redirect_with_input — B', $output);
    }

    /**
     * @throws InvalidRiskMarkerException
     */
    public function test_it_indents_marker_lines_with_leading_whitespace(): void
    {
        $output = (new AttackerContextPromptRenderer())->renderRiskMarkers([
            RiskMarker::create('src/X.php', 7, 'unserialize_call', 'RCE'),
        ]);

        // indent() prepends two spaces; the marker line is indented twice
        // (once within its file block, once for the whole block list).
        self::assertMatchesRegularExpression('/^    L7 unserialize_call — RCE$/m', $output);
        self::assertMatchesRegularExpression('/^  src\/X\.php:$/m', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_renders_previous_findings_grouped_by_type_with_locations(): void
    {
        $output = (new AttackerContextPromptRenderer())->renderPreviousFindings([
            $this->makeVulnerability(VulnerabilityType::SQL_INJECTION, 'src/Repo.php', 10, 20),
            $this->makeVulnerability(VulnerabilityType::SQL_INJECTION, 'src/Other.php', 5, 5),
        ]);

        self::assertStringContainsString('- sql_injection: src/Repo.php:10-20, src/Other.php:5-5', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_indents_previous_finding_lines_with_leading_whitespace(): void
    {
        $output = (new AttackerContextPromptRenderer())->renderPreviousFindings([
            $this->makeVulnerability(VulnerabilityType::SQL_INJECTION, 'src/Repo.php', 10, 20),
        ]);

        self::assertMatchesRegularExpression('/^  - sql_injection: src\/Repo\.php:10-20$/m', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_renders_rejected_findings_grouped_by_type_with_locations(): void
    {
        $output = (new AttackerContextPromptRenderer())->renderRejectedFindings([
            $this->makeVulnerability(VulnerabilityType::MISSING_CSRF_PROTECTION, 'src/Form.php', 12, 12),
            $this->makeVulnerability(VulnerabilityType::MISSING_CSRF_PROTECTION, 'src/Other.php', 3, 4),
        ]);

        self::assertStringContainsString('- missing_csrf_protection: src/Form.php:12-12, src/Other.php:3-4', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_instructs_the_model_not_to_re_report_rejected_findings(): void
    {
        $output = (new AttackerContextPromptRenderer())->renderRejectedFindings([
            $this->makeVulnerability(VulnerabilityType::MISSING_CSRF_PROTECTION, 'src/Form.php', 12, 12),
        ]);

        self::assertStringContainsString('Findings Already Rejected by the Reviewer', $output);
        self::assertStringContainsString('Do NOT re-report these', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_indents_rejected_finding_lines_with_leading_whitespace(): void
    {
        $output = (new AttackerContextPromptRenderer())->renderRejectedFindings([
            $this->makeVulnerability(VulnerabilityType::MISSING_CSRF_PROTECTION, 'src/Form.php', 12, 12),
        ]);

        self::assertMatchesRegularExpression('/^  - missing_csrf_protection: src\/Form\.php:12-12$/m', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    private function makeVulnerability(VulnerabilityType $vulnerabilityType, string $filePath, int $start, int $end): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, VulnerabilitySeverity::HIGH, 'T', 0.9),
            new CodeLocation($filePath, $start, $end),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
