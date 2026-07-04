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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
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
     */
    public function test_writing_a_format_without_a_registered_renderer_throws(): void
    {
        $reportWriter = new ReportWriter([new JsonReportRenderer()], $this->filesystem);
        $symfonyStyle = new SymfonyStyle(new StringInput(''), new BufferedOutput());

        $this->expectException(UnsupportedOutputFormatException::class);
        $this->expectExceptionMessage('No report renderer is registered for output format "sarif".');

        $reportWriter->write($this->makeReport(), OutputFormat::Sarif, null, $symfonyStyle);
    }

    private function makeReport(): AuditReport
    {
        return AuditReport::fromContext(AuditContext::forProject($this->tmpDir));
    }
}
