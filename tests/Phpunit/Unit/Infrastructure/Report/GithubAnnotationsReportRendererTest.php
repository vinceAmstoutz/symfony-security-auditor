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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\GithubAnnotationsReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;

final class GithubAnnotationsReportRendererTest extends AbstractReportRendererTestCase
{
    #[Override]
    protected function createRenderer(): ReportRendererInterface
    {
        return new GithubAnnotationsReportRenderer();
    }

    public function test_it_advertises_the_github_format(): void
    {
        self::assertSame('github', $this->renderer->format());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_renders_nothing_when_no_findings(): void
    {
        self::assertSame('', $this->renderer->render($this->makeReport()));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_it_substitutes_invalid_utf8_instead_of_throwing(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, "Bad\xFFTitle", 0.9),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            'code',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringStartsWith('::error ', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_renders_one_annotation_line_per_finding(): void
    {
        $vulnerability = $this->makeValidatedVuln(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'src/Repo.php', 12);
        $vuln2 = $this->makeValidatedVuln(VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::MEDIUM, 'src/Voter.php', 30);

        $output = $this->renderer->render($this->makeReport($vulnerability, $vuln2));

        $lines = explode("\n", $output);
        self::assertCount(2, $lines);
        self::assertStringStartsWith('::error ', $lines[0]);
        self::assertStringStartsWith('::warning ', $lines[1]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_produces_the_documented_annotation_format(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test Vuln', 0.9),
            new CodeLocation('src/Repo.php', 12, 12),
            new VulnerabilityNarrative('desc', 'vector', 'proof', 'fix'),
            '$q',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertSame('::error file=src/Repo.php,line=12,title=Test Vuln::desc%0A%0ARemediation: fix', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_includes_file_and_start_line_properties(): void
    {
        $vulnerability = $this->makeValidatedVuln(filePath: 'src/Repo.php', lineStart: 12);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('file=src/Repo.php', $output);
        self::assertStringContainsString('line=12', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_omits_end_line_when_it_matches_start_line(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test Vuln', 0.9),
            new CodeLocation('src/Repo.php', 12, 12),
            new VulnerabilityNarrative('desc', 'vector', 'proof', 'fix'),
            '$q',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringNotContainsString('endLine=', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_includes_end_line_when_it_differs_from_start_line(): void
    {
        $vulnerability = $this->makeValidatedVuln(filePath: 'src/Repo.php', lineStart: 12);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('endLine=16', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_includes_the_title_property(): void
    {
        $vulnerability = $this->makeValidatedVuln();

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('title=Test Vuln', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_includes_description_and_remediation_in_the_message(): void
    {
        $vulnerability = $this->makeValidatedVuln();

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('::Test description%0A%0ARemediation: fix', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    #[DataProvider('severityLevelCases')]
    public function test_it_maps_severity_to_the_expected_annotation_level(VulnerabilitySeverity $vulnerabilitySeverity, string $expectedLevel): void
    {
        $vulnerability = $this->makeValidatedVuln(vulnerabilitySeverity: $vulnerabilitySeverity);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringStartsWith('::'.$expectedLevel.' ', $output);
    }

    /** @return iterable<string, array{VulnerabilitySeverity, string}> */
    public static function severityLevelCases(): iterable
    {
        yield 'critical is an error' => [VulnerabilitySeverity::CRITICAL, 'error'];
        yield 'high is an error' => [VulnerabilitySeverity::HIGH, 'error'];
        yield 'medium is a warning' => [VulnerabilitySeverity::MEDIUM, 'warning'];
        yield 'low is a notice' => [VulnerabilitySeverity::LOW, 'notice'];
        yield 'info is a notice' => [VulnerabilitySeverity::INFO, 'notice'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_escapes_comma_colon_newline_and_percent_in_the_title_property(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::TWIG_INJECTION, VulnerabilitySeverity::MEDIUM, "SQLi: a, b\n50% chance", 0.9),
            new CodeLocation('src/Tpl.php', 3, 3),
            new VulnerabilityNarrative('desc', 'vector', 'proof', 'fix'),
            '{{ raw }}',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('title=SQLi%3A a%2C b%0A50%25 chance', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_escapes_newline_and_percent_but_not_comma_or_colon_in_the_message(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::TWIG_INJECTION, VulnerabilitySeverity::MEDIUM, 'Test Vuln', 0.9),
            new CodeLocation('src/Tpl.php', 3, 3),
            new VulnerabilityNarrative("Renders raw, user input: 100% unescaped.\nSee template.", 'vector', 'proof', 'fix'),
            '{{ raw }}',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('::Renders raw, user input: 100%25 unescaped.%0ASee template.', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_escapes_carriage_returns_in_the_title_property(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::TWIG_INJECTION, VulnerabilitySeverity::MEDIUM, "Windows\r\nline endings", 0.9),
            new CodeLocation('src/Tpl.php', 3, 3),
            new VulnerabilityNarrative('desc', 'vector', 'proof', 'fix'),
            '{{ raw }}',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('title=Windows%0D%0Aline endings', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    public function test_it_escapes_percent_before_encoding_the_newline_it_introduces(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::TWIG_INJECTION, VulnerabilitySeverity::MEDIUM, 'Test Vuln', 0.9),
            new CodeLocation('src/Tpl.php', 3, 3),
            new VulnerabilityNarrative("line1\nline2%", 'vector', 'proof', ''),
            '{{ raw }}',
        )->withReviewerValidation(true);

        $output = $this->renderer->render($this->makeReport($vulnerability));

        self::assertStringContainsString('::line1%0Aline2%25', $output);
    }
}
