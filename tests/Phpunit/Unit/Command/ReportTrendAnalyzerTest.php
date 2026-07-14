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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InsufficientTrendReportsException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportDiffer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportFindingsLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportTrendAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\TrendPoint;

final class ReportTrendAnalyzerTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    private ReportTrendAnalyzer $reportTrendAnalyzer;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/report_trend_analyzer_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
        $this->reportTrendAnalyzer = new ReportTrendAnalyzer(new ReportDiffer(new ReportFindingsLoader($this->filesystem)));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws InsufficientTrendReportsException
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_it_produces_one_point_per_report_in_the_given_order(): void
    {
        $first = $this->writeReport('first.json', []);
        $second = $this->writeReport('second.json', []);
        $third = $this->writeReport('third.json', []);

        $reportTrend = $this->reportTrendAnalyzer->analyze([$first, $second, $third]);

        self::assertSame(
            [$first, $second, $third],
            array_map(static fn (TrendPoint $trendPoint): string => $trendPoint->report, $reportTrend->points),
        );
    }

    /**
     * @throws InsufficientTrendReportsException
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_the_first_point_carries_the_total_but_no_new_or_fixed_counts(): void
    {
        $first = $this->writeReport('first.json', [
            $this->vulnerability('SQL Injection', 'src/Repository/A.php'),
            $this->vulnerability('CSRF Missing', 'src/Controller/B.php'),
        ]);
        $second = $this->writeReport('second.json', []);

        $reportTrend = $this->reportTrendAnalyzer->analyze([$first, $second]);

        self::assertSame(
            ['report' => $first, 'total' => 2, 'new' => null, 'fixed' => null],
            $reportTrend->points[0]->toArray(),
        );
    }

    /**
     * @throws InsufficientTrendReportsException
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_a_later_point_counts_new_and_fixed_findings_against_its_predecessor(): void
    {
        $persisting = $this->vulnerability('CSRF Missing', 'src/Controller/A.php');
        $first = $this->writeReport('first.json', [
            $persisting,
            $this->vulnerability('SQL Injection', 'src/Repository/B.php'),
        ]);
        $second = $this->writeReport('second.json', [
            $persisting,
            $this->vulnerability('SSRF via Webhook', 'src/Service/C.php'),
            $this->vulnerability('XSS via Twig', 'templates/d.html.twig'),
        ]);

        $reportTrend = $this->reportTrendAnalyzer->analyze([$first, $second]);

        self::assertSame(
            ['report' => $second, 'total' => 3, 'new' => 2, 'fixed' => 1],
            $reportTrend->points[1]->toArray(),
        );
    }

    /**
     * @throws InsufficientTrendReportsException
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_each_middle_report_is_compared_against_its_own_predecessor_not_the_first(): void
    {
        $onlyInSecond = $this->vulnerability('SSRF via Webhook', 'src/Service/C.php');
        $first = $this->writeReport('first.json', []);
        $second = $this->writeReport('second.json', [$onlyInSecond]);
        $third = $this->writeReport('third.json', [$onlyInSecond]);

        $reportTrend = $this->reportTrendAnalyzer->analyze([$first, $second, $third]);

        self::assertSame(
            ['report' => $third, 'total' => 1, 'new' => 0, 'fixed' => 0],
            $reportTrend->points[2]->toArray(),
        );
    }

    /**
     * @throws InsufficientTrendReportsException
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_fewer_than_two_reports_are_rejected(): void
    {
        $this->expectException(InsufficientTrendReportsException::class);
        $this->expectExceptionMessage('at least two report files ordered oldest to newest, got 1');

        $this->reportTrendAnalyzer->analyze([$this->writeReport('only.json', [])]);
    }

    /**
     * @return array{type: string, file: string, title: string, severity: string, fingerprint: string}
     */
    private function vulnerability(string $title, string $file): array
    {
        return [
            'type' => 'sql_injection',
            'file' => $file,
            'title' => $title,
            'severity' => 'high',
            'fingerprint' => Vulnerability::fingerprintOf('sql_injection', $file, $title),
        ];
    }

    /**
     * @param list<array<string, string>> $vulnerabilities
     */
    private function writeReport(string $filename, array $vulnerabilities): string
    {
        $path = $this->tmpDir.'/'.$filename;
        $this->filesystem->dumpFile($path, json_encode(['vulnerabilities' => $vulnerabilities], \JSON_THROW_ON_ERROR));

        return $path;
    }
}
