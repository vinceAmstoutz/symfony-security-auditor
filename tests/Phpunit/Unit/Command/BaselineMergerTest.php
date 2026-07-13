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
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineMerger;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportFindingsLoader;

final class BaselineMergerTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    private BaselineMerger $baselineMerger;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/baseline_merger_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
        $this->baselineMerger = new BaselineMerger(
            new ReportFindingsLoader($this->filesystem),
            new Baseline($this->filesystem),
            new MockClock('2026-07-13 12:00:00'),
        );
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_every_finding_of_a_report_is_new_when_no_baseline_exists(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection'), $this->finding('XSS')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $this->tmpDir.'/absent.json', false);

        self::assertCount(2, $baselineMergePlan->newFindings);
        self::assertSame([], $baselineMergePlan->keptEntries);
        self::assertSame(0, $baselineMergePlan->prunedCount);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_a_finding_already_in_the_baseline_is_kept_not_added_again(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection'), $this->finding('XSS')]);
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, false);

        self::assertCount(1, $baselineMergePlan->newFindings);
        self::assertSame('XSS', $baselineMergePlan->newFindings[0]->title);
        self::assertCount(1, $baselineMergePlan->keptEntries);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_coverage_is_count_aware_for_findings_sharing_a_fingerprint(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection'), $this->finding('SQL Injection')]);
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, false);

        self::assertCount(1, $baselineMergePlan->newFindings);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_an_entry_also_covers_a_finding_through_its_attacker_fingerprint(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection')]);
        $baseline = $this->writeBaseline([
            [...$this->baselineEntry('Corrected Title'), 'attacker_fingerprint' => $this->fingerprint('SQL Injection')],
        ]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, false);

        self::assertSame([], $baselineMergePlan->newFindings);
        self::assertCount(1, $baselineMergePlan->keptEntries);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_a_stale_entry_survives_without_prune(): void
    {
        $report = $this->writeReport([]);
        $baseline = $this->writeBaseline([$this->baselineEntry('Long Fixed')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, false);

        self::assertCount(1, $baselineMergePlan->keptEntries);
        self::assertSame(0, $baselineMergePlan->prunedCount);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_drops_entries_whose_findings_left_the_report(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection')]);
        $baseline = $this->writeBaseline([
            $this->baselineEntry('SQL Injection'),
            $this->baselineEntry('Long Fixed'),
        ]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertCount(1, $baselineMergePlan->keptEntries);
        self::assertSame(1, $baselineMergePlan->prunedCount);
        self::assertSame([], $baselineMergePlan->newFindings);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_is_count_aware_for_entries_sharing_a_fingerprint(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection')]);
        $baseline = $this->writeBaseline([
            $this->baselineEntry('SQL Injection'),
            $this->baselineEntry('SQL Injection'),
        ]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertCount(1, $baselineMergePlan->keptEntries);
        self::assertSame(1, $baselineMergePlan->prunedCount);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     * @throws UnsafeBaselineWriteException
     */
    public function test_commit_preserves_kept_entries_verbatim_including_their_reasons(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection'), $this->finding('XSS')]);
        $baseline = $this->writeBaseline([
            [...$this->baselineEntry('SQL Injection'), 'reason' => 'input is validated upstream'],
        ]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, false);
        $this->baselineMerger->commit($baseline, $baselineMergePlan, []);

        self::assertSame(
            [
                [...$this->baselineEntry('SQL Injection'), 'reason' => 'input is validated upstream'],
                [
                    'fingerprint' => $this->fingerprint('XSS'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'XSS',
                    'added_at' => '2026-07-13',
                ],
            ],
            $this->decode($baseline),
        );
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     * @throws UnsafeBaselineWriteException
     */
    public function test_commit_appends_a_dated_entry_for_each_new_finding(): void
    {
        $report = $this->writeReport([$this->finding('XSS')]);
        $baseline = $this->tmpDir.'/baseline.json';

        $this->baselineMerger->commit($baseline, $this->baselineMerger->plan($report, $baseline, false), []);

        self::assertSame(
            [
                [
                    'fingerprint' => $this->fingerprint('XSS'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'XSS',
                    'added_at' => '2026-07-13',
                ],
            ],
            $this->decode($baseline),
        );
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     * @throws UnsafeBaselineWriteException
     */
    public function test_commit_records_the_reason_given_for_a_new_finding(): void
    {
        $report = $this->writeReport([$this->finding('XSS')]);
        $baseline = $this->tmpDir.'/baseline.json';

        $this->baselineMerger->commit($baseline, $this->baselineMerger->plan($report, $baseline, false), [0 => 'escaped by Twig autoescape']);

        self::assertSame(
            [
                [
                    'fingerprint' => $this->fingerprint('XSS'),
                    'type' => 'sql_injection',
                    'file' => 'src/Foo.php',
                    'title' => 'XSS',
                    'added_at' => '2026-07-13',
                    'reason' => 'escaped by Twig autoescape',
                ],
            ],
            $this->decode($baseline),
        );
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     * @throws UnsafeBaselineWriteException
     */
    public function test_commit_preserves_a_legacy_plain_string_entry_as_a_string(): void
    {
        $report = $this->writeReport([]);
        $baseline = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($baseline, '["SSA-LEGACY"]');

        $this->baselineMerger->commit($baseline, $this->baselineMerger->plan($report, $baseline, false), []);

        self::assertSame(['SSA-LEGACY'], $this->decode($baseline));
    }

    /**
     * @return array{type: string, file: string, title: string, severity: string, fingerprint: string}
     */
    private function finding(string $title): array
    {
        return [
            'type' => 'sql_injection',
            'file' => 'src/Foo.php',
            'title' => $title,
            'severity' => 'high',
            'fingerprint' => $this->fingerprint($title),
        ];
    }

    private function fingerprint(string $title): string
    {
        return Vulnerability::fingerprintOf('sql_injection', 'src/Foo.php', $title);
    }

    /**
     * @return array<string, string>
     */
    private function baselineEntry(string $title): array
    {
        return [
            'fingerprint' => $this->fingerprint($title),
            'type' => 'sql_injection',
            'file' => 'src/Foo.php',
            'title' => $title,
            'added_at' => '2026-07-03',
        ];
    }

    /**
     * @param list<array<string, string>> $vulnerabilities
     */
    private function writeReport(array $vulnerabilities): string
    {
        $path = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($path, json_encode(['vulnerabilities' => $vulnerabilities], \JSON_THROW_ON_ERROR));

        return $path;
    }

    /**
     * @param list<array<string, string>> $entries
     */
    private function writeBaseline(array $entries): string
    {
        $path = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($path, json_encode($entries, \JSON_THROW_ON_ERROR));

        return $path;
    }

    /**
     * @return array<mixed, mixed>
     */
    private function decode(string $path): array
    {
        $decoded = json_decode((string) file_get_contents($path), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);

        return $decoded;
    }
}
