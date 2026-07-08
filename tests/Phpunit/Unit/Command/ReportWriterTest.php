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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ConsoleReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\HtmlReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JunitReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\MarkdownReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsupportedOutputFormatException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\OutputFormat;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;

final class ReportWriterTest extends TestCase
{
    private ReportWriter $reportWriter;

    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->reportWriter = new ReportWriter([
            new ConsoleReportRenderer(),
            new JsonReportRenderer(),
            new SarifReportRenderer(),
            new HtmlReportRenderer(),
            new MarkdownReportRenderer(),
            new JunitReportRenderer(),
        ], $this->filesystem);
        $this->tmpDir = sys_get_temp_dir().'/report_writer_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     */
    public function test_writing_to_file_announces_save_path_via_success_message(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        $outputFile = $this->tmpDir.'/report.json';

        $this->reportWriter->write($this->makeReport(), OutputFormat::Json, $outputFile, $symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('[OK]', $display);
        self::assertStringContainsString('Report saved to', $display);
        self::assertStringContainsString($outputFile, $display);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     */
    public function test_writing_to_file_persists_content_to_disk(): void
    {
        $symfonyStyle = new SymfonyStyle(new StringInput(''), new BufferedOutput());
        $outputFile = $this->tmpDir.'/report.json';

        $this->reportWriter->write($this->makeReport(), OutputFormat::Json, $outputFile, $symfonyStyle);

        self::assertFileExists($outputFile);
        $content = file_get_contents($outputFile);
        self::assertIsString($content);
        self::assertIsArray(json_decode($content, true));
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     */
    public function test_writing_without_file_streams_content_to_console(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->reportWriter->write($this->makeReport(), OutputFormat::Console, null, $symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('SYMFONY LLM AUDIT REPORT', $display);
        self::assertStringNotContainsString('Report saved to', $display);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_console_output_renders_finding_text_literally_instead_of_as_console_markup(): void
    {
        $vulnerability = Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Finding </> <fg=green>[report clean]</>', 0.9),
            new CodeLocation('src/A.php', 1, 5),
            new VulnerabilityNarrative('desc', 'vec', 'quoted from source: <fg=grey>debug</>', 'fix'),
            'code',
        )->withReviewerValidation(true);
        $bufferedOutput = new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true);
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->reportWriter->write($this->makeReport($vulnerability), OutputFormat::Console, null, $symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Finding </> <fg=green>[report clean]</>', $display);
        self::assertStringContainsString('quoted from source: <fg=grey>debug</>', $display);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     */
    public function test_writing_html_format_streams_an_html_document(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->reportWriter->write($this->makeReport(), OutputFormat::Html, null, $symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('<!doctype html>', $display);
        self::assertStringContainsString('Security Audit Report', $display);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     */
    public function test_writing_junit_format_streams_a_junit_xml_document(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->reportWriter->write($this->makeReport(), OutputFormat::Junit, null, $symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('<testsuites>', $display);
        self::assertStringContainsString('symfony-security-auditor', $display);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     */
    public function test_writing_to_file_creates_missing_parent_directories(): void
    {
        $symfonyStyle = new SymfonyStyle(new StringInput(''), new BufferedOutput());
        $outputFile = $this->tmpDir.'/nested/sub/dir/report.json';

        $this->reportWriter->write($this->makeReport(), OutputFormat::Json, $outputFile, $symfonyStyle);

        self::assertFileExists($outputFile);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     */
    public function test_writing_a_format_without_a_registered_renderer_throws(): void
    {
        $reportWriter = new ReportWriter([new JsonReportRenderer()], $this->filesystem);
        $symfonyStyle = new SymfonyStyle(new StringInput(''), new BufferedOutput());

        $this->expectException(UnsupportedOutputFormatException::class);
        $this->expectExceptionMessage('No report renderer is registered for output format "sarif".');

        $reportWriter->write($this->makeReport(), OutputFormat::Sarif, null, $symfonyStyle);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_writing_sarif_format_with_baselined_fingerprints_marks_the_matching_result_as_suppressed(): void
    {
        $vulnerability = $this->makeVuln();
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->reportWriter->write($this->makeReport($vulnerability), OutputFormat::Sarif, null, $symfonyStyle, [$vulnerability->fingerprint()]);

        $decoded = json_decode($bufferedOutput->fetch(), true);
        self::assertIsArray($decoded);
        $runs = $decoded['runs'] ?? null;
        self::assertIsArray($runs);
        $firstRun = $runs[0] ?? null;
        self::assertIsArray($firstRun);
        $results = $firstRun['results'] ?? null;
        self::assertIsArray($results);
        $firstResult = $results[0] ?? null;
        self::assertIsArray($firstResult);

        self::assertSame(
            [['kind' => 'external', 'justification' => 'Accepted via audit baseline']],
            $firstResult['suppressions'] ?? null,
        );
    }

    /**
     * @throws InvalidAuditContextException
     */
    private function makeReport(Vulnerability ...$vulnerabilities): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
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
    private function makeVuln(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Finding', 0.9),
            new CodeLocation('src/A.php', 1, 5),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            'code',
        )->withReviewerValidation(true);
    }
}
