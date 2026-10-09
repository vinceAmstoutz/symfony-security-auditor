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
     * @param array<string, mixed> $report
     */
    private function writeReport(array $report): string
    {
        $path = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($path, json_encode($report, \JSON_THROW_ON_ERROR));

        return $path;
    }
}
