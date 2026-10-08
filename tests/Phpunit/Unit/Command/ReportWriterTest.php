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
use PHPUnit\Framework\Attributes\DataProvider;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\GithubAnnotationsReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\HtmlReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JunitReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\MarkdownReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeReportWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsupportedOutputFormatException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\OutputFormat;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\WorkflowCommandNeutralizer;

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
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
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
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
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
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_a_report_printed_on_a_github_actions_runner_has_its_workflow_commands_defused(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->runnerReportWriter()->write($this->makeReport($this->makeVulnWithProof("echo ok\n::stop-commands::pwned")), OutputFormat::Console, null, $symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString(':\\:stop-commands::pwned', $display);
        self::assertDoesNotMatchRegularExpression('/^\s*::/m', $display);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_github_annotations_are_left_for_the_runner_to_read(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->runnerReportWriter()->write($this->makeReport(), OutputFormat::GithubAnnotations, null, $symfonyStyle);

        self::assertStringNotContainsString(':\\:', $bufferedOutput->fetch());
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_a_report_saved_to_a_file_is_written_as_rendered(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        $outputFile = $this->tmpDir.'/report.json';

        $this->runnerReportWriter()->write($this->makeReport(), OutputFormat::Json, $outputFile, $symfonyStyle);

        self::assertJson($this->filesystem->readFile($outputFile));
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws UnsafeReportWriteException
     */
    public function test_a_report_kept_on_the_console_of_a_github_actions_runner_has_its_workflow_commands_defused(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        $blockingFile = $this->tmpDir.'/blocking';
        $this->filesystem->dumpFile($blockingFile, 'x');

        $writeFailed = false;
        try {
            $this->runnerReportWriter()->write($this->makeReport($this->makeVulnWithProof('##[warning]forged')), OutputFormat::Json, $blockingFile.'/report.json', $symfonyStyle);
        } catch (ReportWriteFailedException) {
            $writeFailed = true;
        }

        $display = $bufferedOutput->fetch();
        self::assertTrue($writeFailed);
        self::assertStringNotContainsString('##[', $display);
        self::assertJson(trim($display));
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws ReportWriteFailedException
     */
    public function test_a_report_refused_on_a_github_actions_runner_for_a_symlink_has_its_workflow_commands_defused(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        $this->filesystem->dumpFile($this->tmpDir.'/target.txt', '');
        $this->filesystem->symlink($this->tmpDir.'/target.txt', $this->tmpDir.'/report.txt');

        $refused = false;
        try {
            $this->runnerReportWriter()->write($this->makeReport($this->makeVulnWithProof("echo ok\n::stop-commands::pwned")), OutputFormat::Console, $this->tmpDir.'/report.txt', $symfonyStyle);
        } catch (UnsafeReportWriteException) {
            $refused = true;
        }

        self::assertTrue($refused);
        self::assertStringContainsString(':\\:stop-commands::pwned', $bufferedOutput->fetch());
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
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
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
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
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
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
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
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
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
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
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
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
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
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
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_writing_refuses_to_write_through_a_symlinked_output_file(): void
    {
        $symfonyStyle = new SymfonyStyle(new StringInput(''), new BufferedOutput());
        $outputFile = $this->tmpDir.'/report.json';
        $outsideTarget = sys_get_temp_dir().'/report_writer_symlink_target_'.uniqid('', true);
        $this->filesystem->dumpFile($outsideTarget, 'ORIGINAL');
        symlink($outsideTarget, $outputFile);

        try {
            $this->expectException(UnsafeReportWriteException::class);

            $this->reportWriter->write($this->makeReport(), OutputFormat::Json, $outputFile, $symfonyStyle);
        } finally {
            self::assertSame('ORIGINAL', file_get_contents($outsideTarget));
            $this->filesystem->remove($outsideTarget);
        }
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_writing_refuses_to_write_through_a_symlinked_parent_directory(): void
    {
        $symfonyStyle = new SymfonyStyle(new StringInput(''), new BufferedOutput());
        $outsideDir = sys_get_temp_dir().'/report_writer_symlink_dir_'.uniqid('', true);
        $this->filesystem->mkdir($outsideDir);
        $nestedDir = $this->tmpDir.'/nested';
        symlink($outsideDir, $nestedDir);

        try {
            $this->expectException(UnsafeReportWriteException::class);

            $this->reportWriter->write($this->makeReport(), OutputFormat::Json, $nestedDir.'/report.json', $symfonyStyle);
        } finally {
            self::assertSame([], glob($outsideDir.'/*'));
            $this->filesystem->remove($outsideDir);
        }
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_writing_wraps_a_filesystem_write_failure_in_a_project_defined_exception(): void
    {
        $symfonyStyle = new SymfonyStyle(new StringInput(''), new BufferedOutput());
        $blockerPath = $this->tmpDir.'/blocker';
        file_put_contents($blockerPath, 'not a directory');
        $outputFile = $blockerPath.'/report.json';

        $this->expectException(ReportWriteFailedException::class);

        $this->reportWriter->write($this->makeReport(), OutputFormat::Json, $outputFile, $symfonyStyle);
    }

    private function runnerReportWriter(): ReportWriter
    {
        return new ReportWriter([new ConsoleReportRenderer(), new JsonReportRenderer(), new GithubAnnotationsReportRenderer()], $this->filesystem, new WorkflowCommandNeutralizer(true));
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
    private function makeVulnWithProof(string $proof): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Finding', 0.9),
            new CodeLocation('src/A.php', 1, 5),
            new VulnerabilityNarrative('desc', 'vec', $proof, 'fix'),
            'code',
        )->withReviewerValidation(true);
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

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_a_report_that_cannot_reach_its_file_is_kept_on_the_console(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        $blockingFile = $this->tmpDir.'/blocking';
        $this->filesystem->dumpFile($blockingFile, 'x');

        $writeFailed = false;
        try {
            $this->reportWriter->write($this->makeReport(), OutputFormat::Json, $blockingFile.'/report.json', $symfonyStyle);
        } catch (ReportWriteFailedException) {
            $writeFailed = true;
        }

        self::assertTrue($writeFailed);
        self::assertJson(trim($bufferedOutput->fetch()));
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_a_report_refused_for_a_symlinked_file_is_kept_on_the_console(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);
        symlink($this->tmpDir.'/elsewhere.json', $this->tmpDir.'/report.json');

        $writeRefused = false;
        try {
            $this->reportWriter->write($this->makeReport(), OutputFormat::Json, $this->tmpDir.'/report.json', $symfonyStyle);
        } catch (UnsafeReportWriteException) {
            $writeRefused = true;
        }

        self::assertTrue($writeRefused);
        self::assertJson(trim($bufferedOutput->fetch()));
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_assert_writable_accepts_a_new_file_under_directories_that_do_not_exist_yet(): void
    {
        $outputFile = $this->tmpDir.'/build/reports/report.json';

        $this->reportWriter->assertWritable($outputFile, $this->tmpDir);

        self::assertDirectoryExists($this->tmpDir.'/build/reports');
        self::assertFileDoesNotExist($outputFile);
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_assert_writable_accepts_an_existing_writable_file(): void
    {
        $outputFile = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($outputFile, 'previous run');

        $this->reportWriter->assertWritable($outputFile, $this->tmpDir);

        self::assertStringEqualsFile($outputFile, 'previous run');
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_assert_writable_refuses_a_symlinked_output_file(): void
    {
        symlink($this->tmpDir.'/elsewhere.json', $this->tmpDir.'/report.json');

        $this->expectException(UnsafeReportWriteException::class);

        $this->reportWriter->assertWritable($this->tmpDir.'/report.json', $this->tmpDir);
    }

    /**
     * @throws UnsupportedOutputFormatException
     * @throws InvalidAuditContextException
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_writing_refuses_a_path_into_the_audited_project_through_a_symlinked_directory_above_its_parent(): void
    {
        $symfonyStyle = new SymfonyStyle(new StringInput(''), new BufferedOutput());
        $outsideDir = sys_get_temp_dir().'/report_writer_symlink_build_'.uniqid('', true);
        $this->filesystem->mkdir($outsideDir.'/reports');
        symlink($outsideDir, $this->tmpDir.'/build');

        try {
            $this->expectException(UnsafeReportWriteException::class);

            $this->reportWriter->write($this->makeReport(), OutputFormat::Json, $this->tmpDir.'/build/reports/report.json', $symfonyStyle);
        } finally {
            self::assertSame([], glob($outsideDir.'/reports/*'));
            $this->filesystem->remove($outsideDir);
        }
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_assert_writable_refuses_a_path_into_the_audited_project_through_a_symlinked_directory_above_its_parent(): void
    {
        $outsideDir = sys_get_temp_dir().'/report_writer_symlink_build_'.uniqid('', true);
        $this->filesystem->mkdir($outsideDir.'/reports');
        symlink($outsideDir, $this->tmpDir.'/build');

        try {
            $this->expectException(UnsafeReportWriteException::class);

            $this->reportWriter->assertWritable($this->tmpDir.'/build/reports/report.json', $this->tmpDir);
        } finally {
            $this->filesystem->remove($outsideDir);
        }
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_assert_writable_refuses_a_path_beneath_a_regular_file(): void
    {
        $blockingFile = $this->tmpDir.'/blocking';
        $this->filesystem->dumpFile($blockingFile, 'x');

        $this->expectException(ReportWriteFailedException::class);
        $this->expectExceptionMessage('before the audit spends anything');

        $this->reportWriter->assertWritable($blockingFile.'/report.json', $this->tmpDir);
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    #[DataProvider('directorySeparators')]
    public function test_assert_writable_refuses_a_path_that_names_a_directory(string $separator): void
    {
        $this->expectException(ReportWriteFailedException::class);
        $this->expectExceptionMessage('names a directory');

        $this->reportWriter->assertWritable($this->tmpDir.'/reports'.$separator, $this->tmpDir);
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_assert_writable_accepts_a_path_that_is_not_utf_8(): void
    {
        $outputFile = $this->tmpDir."/r\xFF.json";

        $this->reportWriter->assertWritable($outputFile, $this->tmpDir);

        self::assertFileDoesNotExist($outputFile);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function directorySeparators(): iterable
    {
        yield 'a trailing slash' => ['/'];
        yield 'a trailing backslash' => ['\\'];
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_assert_writable_refuses_an_existing_output_file_that_is_not_a_regular_file(): void
    {
        $pipe = $this->tmpDir.'/report.pipe';
        posix_mkfifo($pipe, 0o600);

        $this->expectException(ReportWriteFailedException::class);
        $this->expectExceptionMessage('before the audit spends anything');

        $this->reportWriter->assertWritable($pipe, $this->tmpDir);
    }

    /**
     * @throws UnsafeReportWriteException
     * @throws ReportWriteFailedException
     */
    public function test_assert_writable_refuses_a_directory_as_the_output_file(): void
    {
        $this->expectException(ReportWriteFailedException::class);

        $this->reportWriter->assertWritable($this->tmpDir, $this->tmpDir);
    }
}
