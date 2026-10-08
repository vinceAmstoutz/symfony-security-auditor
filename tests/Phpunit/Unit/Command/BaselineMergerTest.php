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
     */
    public function test_prune_keeps_entries_that_follow_a_pruned_one(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection')]);
        $baseline = $this->writeBaseline([
            $this->baselineEntry('Long Fixed'),
            $this->baselineEntry('SQL Injection'),
        ]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertCount(1, $baselineMergePlan->keptEntries);
        self::assertSame($this->fingerprint('SQL Injection'), $baselineMergePlan->keptEntries[0]->fingerprint);
        self::assertSame(1, $baselineMergePlan->prunedCount);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_keeps_every_entry_matched_by_a_distinct_finding(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection'), $this->finding('XSS')]);
        $baseline = $this->writeBaseline([
            $this->baselineEntry('SQL Injection'),
            $this->baselineEntry('XSS'),
        ]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertCount(2, $baselineMergePlan->keptEntries);
        self::assertSame(0, $baselineMergePlan->prunedCount);
    }

    /**
     * A report that never analyzed a file says nothing about the findings in
     * it, so a prune keeps their accepted entries — and the reasons a
     * maintainer wrote for them.
     *
     * @param list<array{stage: string, file: string, status: string}> $coverage
     *
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('ledgersThatNeverSayTheFileWasAnalyzed')]
    public function test_prune_keeps_an_entry_whose_file_the_report_never_analyzed(array $coverage): void
    {
        $report = $this->writeReportWithCoverage([], $coverage);
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(0, $baselineMergePlan->prunedCount);
        self::assertCount(1, $baselineMergePlan->keptEntries);
    }

    /**
     * @return iterable<string, array{list<array{stage: string, file: string, status: string}>}>
     */
    public static function ledgersThatNeverSayTheFileWasAnalyzed(): iterable
    {
        yield 'its file could not be analyzed' => [[['stage' => 'attacker', 'file' => 'src/Ok.php', 'status' => 'analyzed'], ['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'errored']]];
        yield 'its file was outside the scope of the run' => [[['stage' => 'attacker', 'file' => 'src/Ok.php', 'status' => 'analyzed']]];
        yield 'its file was skipped by the lean pre-scan' => [[['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'skipped']]];
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_drops_an_entry_whose_file_the_report_analyzed_clean(): void
    {
        $report = $this->writeReportWithCoverage([], [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'analyzed']]);
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(1, $baselineMergePlan->prunedCount);
        self::assertSame([], $baselineMergePlan->keptEntries);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_drops_an_entry_whose_file_a_complete_full_run_no_longer_lists(): void
    {
        $report = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($report, json_encode([
            'complete' => true,
            'scope' => ['since' => null, 'paths' => []],
            'vulnerabilities' => [],
            'coverage' => [['stage' => 'attacker', 'file' => 'src/Ok.php', 'status' => 'analyzed']],
        ], \JSON_THROW_ON_ERROR));
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(1, $baselineMergePlan->prunedCount);
        self::assertSame([], $baselineMergePlan->keptEntries);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_keeps_every_entry_when_the_scan_of_a_complete_run_found_no_file(): void
    {
        $report = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($report, json_encode([
            'files_scanned' => 0,
            'complete' => true,
            'scope' => ['since' => null, 'paths' => []],
            'vulnerabilities' => [],
            'coverage' => [],
        ], \JSON_THROW_ON_ERROR));
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(0, $baselineMergePlan->prunedCount);
        self::assertCount(1, $baselineMergePlan->keptEntries);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_drops_a_legacy_entry_it_cannot_place_in_a_file(): void
    {
        $report = $this->writeReportWithCoverage([], [['stage' => 'attacker', 'file' => 'src/Ok.php', 'status' => 'analyzed']]);
        $baseline = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($baseline, '["SSA-LEGACY"]');

        self::assertSame(1, $this->baselineMerger->plan($report, $baseline, true)->prunedCount);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     * @throws UnsafeBaselineWriteException
     */
    public function test_a_prune_keeps_the_reason_of_an_entry_whose_file_the_report_could_not_analyze(): void
    {
        $report = $this->writeReportWithCoverage([], [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'errored']]);
        $baseline = $this->writeBaseline([[...$this->baselineEntry('SQL Injection'), 'reason' => 'The id is cast to int upstream.']]);

        $this->baselineMerger->commit($baseline, $this->baselineMerger->plan($report, $baseline, true), []);

        self::assertSame([[...$this->baselineEntry('SQL Injection'), 'reason' => 'The id is cast to int upstream.']], $this->decode($baseline));
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
    public function test_commit_keeps_the_non_ascii_text_of_a_kept_entry_as_it_was_written(): void
    {
        $report = $this->writeReport([$this->finding('SQL Injection')]);
        $baseline = $this->tmpDir.'/baseline.json';
        $entry = [...$this->baselineEntry('SQL Injection'), 'reason' => 'Les paramètres sont liés par le dépôt — 日本語'];
        $this->filesystem->dumpFile($baseline, json_encode([$entry], \JSON_PRETTY_PRINT | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR));

        $this->baselineMerger->commit($baseline, $this->baselineMerger->plan($report, $baseline, false), []);

        self::assertStringContainsString('"reason": "Les paramètres sont liés par le dépôt — 日本語"', (string) file_get_contents($baseline));
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
     * @param list<array<string, string>>                              $vulnerabilities
     * @param list<array{stage: string, file: string, status: string}> $coverage
     */
    private function writeReportWithCoverage(array $vulnerabilities, array $coverage): string
    {
        $path = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($path, json_encode(['vulnerabilities' => $vulnerabilities, 'coverage' => $coverage], \JSON_THROW_ON_ERROR));

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
