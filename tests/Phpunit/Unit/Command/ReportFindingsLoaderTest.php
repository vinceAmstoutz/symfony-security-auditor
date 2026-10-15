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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportFindingsLoader;

final class ReportFindingsLoaderTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/report_findings_loader_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_a_report_without_suppressed_fingerprints_lists_none(): void
    {
        $path = $this->writeReport(['vulnerabilities' => []]);

        self::assertSame([], (new ReportFindingsLoader($this->filesystem))->load($path)->suppressedFingerprints);
    }

    /**
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_it_reads_the_fingerprints_the_report_lists_as_suppressed_once_per_occurrence(): void
    {
        $path = $this->writeReport(['vulnerabilities' => [], 'suppressed_fingerprints' => ['SSA-AAA', 'SSA-BBB', 'SSA-AAA']]);

        self::assertSame(['SSA-AAA', 'SSA-BBB', 'SSA-AAA'], (new ReportFindingsLoader($this->filesystem))->load($path)->suppressedFingerprints);
    }

    /**
     * @param list<string> $expected
     *
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('suppressedFingerprintsThatAreNotAListOfStrings')]
    public function test_it_keeps_only_the_strings_of_a_suppressed_list(mixed $suppressed, array $expected): void
    {
        $path = $this->writeReport(['vulnerabilities' => [], 'suppressed_fingerprints' => $suppressed]);

        self::assertSame($expected, (new ReportFindingsLoader($this->filesystem))->load($path)->suppressedFingerprints);
    }

    /**
     * @return iterable<string, array{mixed, list<string>}>
     */
    public static function suppressedFingerprintsThatAreNotAListOfStrings(): iterable
    {
        yield 'a string instead of a list' => ['SSA-AAA', []];
        yield 'null' => [null, []];
        yield 'a list holding no string' => [[42, null, ['SSA-AAA']], []];
        yield 'a list holding strings among other values' => [[42, 'SSA-AAA', null, 'SSA-BBB'], ['SSA-AAA', 'SSA-BBB']];
    }

    /**
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_it_reads_the_baseline_fingerprints_that_left_the_suppressed_findings_out(): void
    {
        $path = $this->writeReport(['vulnerabilities' => [], 'suppressed_fingerprints' => ['SSA-XSS', 'SSA-AAA'], 'suppressed_baseline_fingerprints' => ['SSA-TWIG', 'SSA-AAA']]);

        $loadedReport = (new ReportFindingsLoader($this->filesystem))->load($path);

        self::assertSame(['SSA-XSS', 'SSA-AAA'], $loadedReport->suppressedFingerprints);
        self::assertSame(['SSA-TWIG', 'SSA-AAA'], $loadedReport->suppressedBaselineFingerprints);
    }

    /**
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_a_report_written_before_the_baseline_fingerprints_were_listed_takes_its_suppressed_fingerprints_for_them(): void
    {
        $path = $this->writeReport(['vulnerabilities' => [], 'suppressed_fingerprints' => ['SSA-TWIG', 'SSA-AAA']]);

        self::assertSame(['SSA-TWIG', 'SSA-AAA'], (new ReportFindingsLoader($this->filesystem))->load($path)->suppressedBaselineFingerprints);
    }

    /**
     * @param list<string> $expected
     *
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('suppressedBaselineFingerprintsThatAreNotAListOfStrings')]
    public function test_it_keeps_only_the_strings_of_a_suppressed_baseline_list(mixed $suppressed, array $expected): void
    {
        $path = $this->writeReport(['vulnerabilities' => [], 'suppressed_fingerprints' => ['SSA-OTHER'], 'suppressed_baseline_fingerprints' => $suppressed]);

        self::assertSame($expected, (new ReportFindingsLoader($this->filesystem))->load($path)->suppressedBaselineFingerprints);
    }

    /**
     * @return iterable<string, array{mixed, list<string>}>
     */
    public static function suppressedBaselineFingerprintsThatAreNotAListOfStrings(): iterable
    {
        yield 'a string instead of a list' => ['SSA-AAA', []];
        yield 'null, as if the key were missing' => [null, ['SSA-OTHER']];
        yield 'a list holding no string' => [[42, null, ['SSA-AAA']], []];
        yield 'a list holding strings among other values' => [[42, 'SSA-AAA', null, 'SSA-BBB'], ['SSA-AAA', 'SSA-BBB']];
    }

    /**
     * @param array<string, mixed> $report
     *
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('projectsAReportNames')]
    public function test_it_reads_the_project_the_report_audited(array $report, ?string $expected): void
    {
        $path = $this->writeReport(['vulnerabilities' => [], ...$report]);

        self::assertSame($expected, (new ReportFindingsLoader($this->filesystem))->load($path)->projectPath);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string|null}>
     */
    public static function projectsAReportNames(): iterable
    {
        yield 'a project' => [['project' => '/abs/project', 'suppressed_fingerprints' => []], '/abs/project'];
        yield 'no project' => [['suppressed_fingerprints' => []], ''];
        yield 'a project that is not a string' => [['project' => 42, 'suppressed_fingerprints' => []], ''];
        yield 'a project, in a report written before it listed suppressed fingerprints' => [['project' => '/abs/project'], null];
    }

    /**
     * @param array<string, mixed> $report
     */
    private function writeReport(array $report): string
    {
        $path = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($path, json_encode($report, \JSON_THROW_ON_ERROR));

        return $path;
    }
}
