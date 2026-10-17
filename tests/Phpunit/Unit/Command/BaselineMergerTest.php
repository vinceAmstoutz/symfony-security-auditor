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

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Random\Engine\Xoshiro256StarStar;
use Random\Randomizer;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineEntry;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineMergePlan;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineMerger;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffFinding;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportFindingsLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\Fixture\PairwiseBaselineMerge;

final class BaselineMergerTest extends TestCase
{
    private const int GENERATED_CASES = 200;

    private const int THOUSANDS = 2000;

    private const array GENERATED_FILES = ['src/Foo.php', 'src/Bar.php'];

    private const array GENERATED_TYPES = ['xss', 'twig_injection', 'sensitive_data_exposure', 'sql_injection', 'custom_type'];

    private const array GENERATED_TITLES = ['Injection', 'Other'];

    private const array GENERATED_STATUSES = ['analyzed', 'errored', null];

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
    public function test_prune_drops_an_entry_whose_file_the_scan_left_out_as_it_did_before_the_scan_listed_it(): void
    {
        $report = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($report, json_encode([
            'complete' => true,
            'scope' => ['since' => null, 'paths' => []],
            'vulnerabilities' => [],
            'coverage' => [
                ['stage' => 'scan', 'file' => 'src/Foo.php', 'status' => 'skipped'],
                ['stage' => 'attacker', 'file' => 'src/Ok.php', 'status' => 'analyzed'],
            ],
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
     * A run under a baseline leaves the findings it accepted out of its report,
     * so the report lists them by fingerprint instead: their entries, and the
     * reasons a maintainer wrote for them, outlive a prune.
     *
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_keeps_an_entry_whose_finding_the_report_lists_as_suppressed(): void
    {
        $report = $this->writeReportWithSuppressed([], [$this->fingerprint('SQL Injection')]);
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(0, $baselineMergePlan->prunedCount);
        self::assertCount(1, $baselineMergePlan->keptEntries);
        self::assertSame([], $baselineMergePlan->newFindings);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_still_drops_an_entry_no_suppressed_finding_matches(): void
    {
        $report = $this->writeReportWithSuppressed([], [$this->fingerprint('SQL Injection')]);
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection'), $this->baselineEntry('Long Fixed')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(1, $baselineMergePlan->prunedCount);
        self::assertCount(1, $baselineMergePlan->keptEntries);
        self::assertSame($this->fingerprint('SQL Injection'), $baselineMergePlan->keptEntries[0]->fingerprint);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_keeps_an_entry_through_its_attacker_fingerprint_when_the_report_lists_that_one_as_suppressed(): void
    {
        $report = $this->writeReportWithSuppressed([], [$this->fingerprint('SQL Injection')]);
        $baseline = $this->writeBaseline([
            [...$this->baselineEntry('Corrected Title'), 'attacker_fingerprint' => $this->fingerprint('SQL Injection')],
        ]);

        self::assertSame(0, $this->baselineMerger->plan($report, $baseline, true)->prunedCount);
    }

    /**
     * A baseline written before `xss` existed holds the finding under the type
     * the model reported it as then: the report lists the finding under its
     * own `xss` fingerprint and the baseline fingerprint that accepted it
     * beside it.
     *
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_keeps_an_entry_through_the_baseline_fingerprint_a_suppressed_finding_was_accepted_by(): void
    {
        $report = $this->writeReportWithSuppressed([], [$this->fingerprint('XSS')], [$this->fingerprint('SQL Injection')]);
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
    public function test_prune_drops_an_entry_only_the_fingerprint_a_suppressed_finding_is_listed_under_matches(): void
    {
        $report = $this->writeReportWithSuppressed([], [$this->fingerprint('XSS')], [$this->fingerprint('SQL Injection')]);
        $baseline = $this->writeBaseline([$this->baselineEntry('XSS')]);

        self::assertSame(1, $this->baselineMerger->plan($report, $baseline, true)->prunedCount);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_counts_each_suppressed_occurrence_once(): void
    {
        $report = $this->writeReportWithSuppressed([], [$this->fingerprint('SQL Injection')]);
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection'), $this->baselineEntry('SQL Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(1, $baselineMergePlan->prunedCount);
        self::assertCount(1, $baselineMergePlan->keptEntries);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_counts_a_suppressed_occurrence_beside_a_listed_one(): void
    {
        $report = $this->writeReportWithSuppressed([$this->finding('SQL Injection')], [$this->fingerprint('SQL Injection')]);
        $baseline = $this->writeBaseline([$this->baselineEntry('SQL Injection'), $this->baselineEntry('SQL Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(0, $baselineMergePlan->prunedCount);
        self::assertCount(2, $baselineMergePlan->keptEntries);
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
    #[DataProvider('otherNamesOfTheFindingABaselineWrittenBeforeHolds')]
    public function test_an_entry_holding_the_finding_under_a_name_it_had_before_keeps_its_reason_and_adds_no_duplicate(string $reportedType, string $entryType, string $entryFile): void
    {
        $report = $this->writeCompleteReportOfTheProject([$this->findingInFoo($reportedType, 'Injection')]);
        $entry = $this->entryInFoo($entryType, $entryFile, 'Injection');
        $baseline = $this->writeBaseline([[...$entry, 'reason' => 'The value is escaped upstream.']]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);
        $mergePlan = $this->baselineMerger->plan($report, $baseline, false);
        $this->baselineMerger->commit($baseline, $baselineMergePlan, []);

        self::assertSame([0, [], []], [$baselineMergePlan->prunedCount, $baselineMergePlan->newFindings, $mergePlan->newFindings]);
        self::assertSame([[...$entry, 'reason' => 'The value is escaped upstream.']], $this->decode($baseline));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function otherNamesOfTheFindingABaselineWrittenBeforeHolds(): iterable
    {
        yield 'a path with a leading dot slash' => ['sql_injection', 'sql_injection', './src/Foo.php'];
        yield 'a path with backslashes' => ['sql_injection', 'sql_injection', 'src\\Foo.php'];
        yield 'a path with a leading slash' => ['sql_injection', 'sql_injection', '/src/Foo.php'];
        yield 'an absolute path inside the project' => ['sql_injection', 'sql_injection', '/abs/project/src/Foo.php'];
        yield 'the type twig_injection' => ['xss', 'twig_injection', 'src/Foo.php'];
        yield 'the type sensitive_data_exposure' => ['xss', 'sensitive_data_exposure', 'src/Foo.php'];
        yield 'a former type and a path with a leading dot slash' => ['xss', 'twig_injection', './src/Foo.php'];
        yield 'a path with a leading dot slash, for a type this release does not know' => ['custom_type', 'custom_type', './src/Foo.php'];
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_a_legacy_entry_holding_the_finding_under_a_former_type_covers_it(): void
    {
        $report = $this->writeCompleteReportOfTheProject([$this->findingInFoo('xss', 'Injection')]);
        $baseline = $this->tmpDir.'/baseline.json';
        $this->filesystem->dumpFile($baseline, json_encode([Vulnerability::fingerprintOf('twig_injection', 'src/Foo.php', 'Injection')], \JSON_THROW_ON_ERROR));

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame([0, 1, []], [$baselineMergePlan->prunedCount, \count($baselineMergePlan->keptEntries), $baselineMergePlan->newFindings]);
    }

    /**
     * @param array<string, string> $entry
     *
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('entriesOfAnotherFinding')]
    public function test_an_entry_of_another_finding_is_pruned_from_a_complete_run_and_covers_nothing(array $entry): void
    {
        $report = $this->writeCompleteReportOfTheProject([$this->findingInFoo('sql_injection', 'Injection')]);
        $baseline = $this->writeBaseline([$entry]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(
            [1, [], [$this->findingInFoo('sql_injection', 'Injection')]],
            [$baselineMergePlan->prunedCount, $baselineMergePlan->keptEntries, array_map(static fn (DiffFinding $diffFinding): array => [...$diffFinding->toArray()], $baselineMergePlan->newFindings)],
        );
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function entriesOfAnotherFinding(): iterable
    {
        $entry = static fn (string $type, string $file, string $title, ?string $fingerprintFile = null): array => [
            'fingerprint' => Vulnerability::fingerprintOf($type, $fingerprintFile ?? $file, $title),
            'type' => $type,
            'file' => $file,
            'title' => $title,
        ];

        yield 'another file' => [$entry('sql_injection', 'src/Bar.php', 'Injection')];
        yield 'another file with a leading dot slash' => [$entry('sql_injection', './src/Bar.php', 'Injection')];
        yield 'a file of the same name under another directory' => [$entry('sql_injection', 'lib/src/Foo.php', 'Injection')];
        yield 'the same path under another project' => [$entry('sql_injection', '/elsewhere/src/Foo.php', 'Injection')];
        yield 'another title' => [$entry('sql_injection', './src/Foo.php', 'Other')];
        yield 'a type the finding never had' => [$entry('twig_injection', './src/Foo.php', 'Injection')];
        yield 'a fingerprint of another file than the one it names' => [$entry('sql_injection', './src/Foo.php', 'Injection', 'src/Bar.php')];
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_an_entry_holding_the_finding_under_another_path_covers_one_occurrence_and_no_other_finding(): void
    {
        $report = $this->writeCompleteReportOfTheProject([
            $this->findingInFoo('sql_injection', 'Other'),
            $this->findingInFoo('sql_injection', 'Injection'),
            $this->findingInFoo('sql_injection', 'Injection'),
        ]);
        $baseline = $this->writeBaseline([$this->entryInFoo('sql_injection', './src/Foo.php', 'Injection')]);

        self::assertSame(
            [['Other', 'Injection'], ['Other', 'Injection']],
            [
                array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->title, $this->baselineMerger->plan($report, $baseline, true)->newFindings),
                array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->title, $this->baselineMerger->plan($report, $baseline, false)->newFindings),
            ],
        );
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_keeps_one_entry_holding_the_finding_under_another_path_per_occurrence_of_it(): void
    {
        $report = $this->writeCompleteReportOfTheProject([$this->findingInFoo('sql_injection', 'Injection')]);
        $baseline = $this->writeBaseline([
            $this->entryInFoo('sql_injection', './src/Foo.php', 'Injection'),
            $this->entryInFoo('sql_injection', './src/Foo.php', 'Injection'),
        ]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame([1, 1], [$baselineMergePlan->prunedCount, \count($baselineMergePlan->keptEntries)]);
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('respelledPathsOfFoo')]
    public function test_an_entry_holding_the_finding_under_another_path_covers_nothing_in_a_report_written_before_findings_were_named_by_their_project_file(string $entryFile): void
    {
        $report = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($report, json_encode([
            'project' => '/abs/project',
            'complete' => true,
            'scope' => ['since' => null, 'paths' => []],
            'vulnerabilities' => [$this->findingInFoo('sql_injection', 'Injection')],
            'coverage' => [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'analyzed']],
        ], \JSON_THROW_ON_ERROR));
        $baseline = $this->writeBaseline([$this->entryInFoo('sql_injection', $entryFile, 'Injection')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame([1, ['Injection']], [$baselineMergePlan->prunedCount, array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->title, $baselineMergePlan->newFindings)]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function respelledPathsOfFoo(): iterable
    {
        yield 'with a leading dot slash' => ['./src/Foo.php'];
        yield 'with a leading slash' => ['/src/Foo.php'];
        yield 'as an absolute path inside the project' => ['/abs/project/src/Foo.php'];
    }

    /**
     * @param list<array<string, string>> $entries
     * @param list<string>                $expectedNewTypes
     *
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('entriesInOrderOfAcceptance')]
    public function test_a_finding_spends_the_credit_of_the_first_entry_holding_it_under_a_former_name(array $entries, array $expectedNewTypes): void
    {
        $report = $this->writeCompleteReportOfTheProject([$this->findingInFoo('xss', 'Injection'), $this->findingInFoo('twig_injection', 'Injection')]);
        $baseline = $this->writeBaseline($entries);

        $newFindings = $this->baselineMerger->plan($report, $baseline, false)->newFindings;

        self::assertSame($expectedNewTypes, array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->type, $newFindings));
    }

    /**
     * @return iterable<string, array{list<array<string, string>>, list<string>}>
     */
    public static function entriesInOrderOfAcceptance(): iterable
    {
        $twigEntry = self::respelledEntryInFoo('twig_injection');
        $sensitiveDataEntry = self::respelledEntryInFoo('sensitive_data_exposure');

        yield 'the entry the second finding also needs comes first' => [[$twigEntry, $sensitiveDataEntry], ['twig_injection']];
        yield 'the entry only the first finding holds comes first' => [[$sensitiveDataEntry, $twigEntry], []];
    }

    /**
     * @param list<array<string, string>> $vulnerabilities
     * @param list<array<string, string>> $expectedKeptEntries
     * @param list<string>                $expectedNewTypes
     *
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('findingsInReportOrder')]
    public function test_prune_spends_the_first_finding_of_the_report_an_entry_holds_under_a_former_name(array $vulnerabilities, int $expectedPrunedCount, array $expectedKeptEntries, array $expectedNewTypes): void
    {
        $report = $this->writeCompleteReportOfTheProject($vulnerabilities);
        $baseline = $this->writeBaseline([self::respelledEntryInFoo('twig_injection'), self::respelledEntryInFoo('sensitive_data_exposure')]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(
            [$expectedPrunedCount, $expectedKeptEntries, $expectedNewTypes],
            [
                $baselineMergePlan->prunedCount,
                array_map(static fn (BaselineEntry $baselineEntry): array|string => $baselineEntry->raw, $baselineMergePlan->keptEntries),
                array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->type, $baselineMergePlan->newFindings),
            ],
        );
    }

    /**
     * @return iterable<string, array{list<array<string, string>>, int, list<array<string, string>>, list<string>}>
     */
    public static function findingsInReportOrder(): iterable
    {
        $xss = ['fingerprint' => Vulnerability::fingerprintOf('xss', 'src/Foo.php', 'Injection'), 'type' => 'xss', 'file' => 'src/Foo.php', 'title' => 'Injection', 'severity' => 'high'];
        $twig = ['fingerprint' => Vulnerability::fingerprintOf('twig_injection', 'src/Foo.php', 'Injection'), 'type' => 'twig_injection', 'file' => 'src/Foo.php', 'title' => 'Injection', 'severity' => 'high'];

        yield 'the finding both entries hold comes first' => [[$xss, $twig], 1, [self::respelledEntryInFoo('twig_injection')], ['twig_injection']];
        yield 'the finding one entry holds alone comes first' => [[$twig, $xss], 0, [self::respelledEntryInFoo('twig_injection'), self::respelledEntryInFoo('sensitive_data_exposure')], []];
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_prune_spends_the_first_finding_an_entry_holds_whether_it_holds_it_under_its_own_path_or_another_spelling(): void
    {
        $respelledFinding = ['fingerprint' => Vulnerability::fingerprintOf('xss', './src/Foo.php', 'Injection'), 'type' => 'xss', 'file' => './src/Foo.php', 'title' => 'Injection', 'severity' => 'high'];
        $report = $this->writeCompleteReportOfTheProject([$respelledFinding, $this->findingInFoo('xss', 'Injection')]);
        $twigEntry = $this->entryInFoo('twig_injection', 'src/Foo.php', 'Injection');
        $baseline = $this->writeGenerated('baseline.json', [$twigEntry, $respelledFinding['fingerprint']]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(
            [1, [$twigEntry], [$this->findingInFoo('xss', 'Injection')]],
            [$baselineMergePlan->prunedCount, $this->rawOf($baselineMergePlan->keptEntries), $this->arraysOf($baselineMergePlan->newFindings)],
        );
    }

    /**
     * @param array<string, string> $heldEntry
     *
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('entriesHoldingEveryOccurrence')]
    public function test_prune_spends_the_first_occurrence_an_entry_holds_whatever_fingerprint_the_report_lists_it_under(array $heldEntry): void
    {
        $listedUnder = static fn (string $fingerprint): array => ['fingerprint' => $fingerprint, 'type' => 'xss', 'file' => 'src/Foo.php', 'title' => 'Injection', 'severity' => 'high'];
        $report = $this->writeCompleteReportOfTheProject([$listedUnder('SSA-00000000000A'), $listedUnder('SSA-00000000000B'), $listedUnder('SSA-00000000000A')]);
        $baseline = $this->writeBaseline([$heldEntry, ['fingerprint' => 'SSA-00000000000B', 'type' => 'xss', 'file' => 'src/Foo.php', 'title' => 'Injection']]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(
            [0, 2, ['SSA-00000000000A']],
            [$baselineMergePlan->prunedCount, \count($baselineMergePlan->keptEntries), array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->fingerprint, $baselineMergePlan->newFindings)],
        );
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function entriesHoldingEveryOccurrence(): iterable
    {
        yield 'an entry naming no file, under a former type' => [['fingerprint' => Vulnerability::fingerprintOf('twig_injection', 'src/Foo.php', 'Injection'), 'type' => 'twig_injection']];
        yield 'an entry naming the file under another spelling' => [self::respelledEntryInFoo('twig_injection')];
    }

    /**
     * @param list<array<string, string>> $entries
     *
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[DataProvider('baselinesRepeatingAnEntry')]
    public function test_a_finding_spends_the_credit_of_the_first_of_the_entries_sharing_a_fingerprint(array $entries): void
    {
        $report = $this->writeCompleteReportOfTheProject([$this->findingInFoo('xss', 'Injection'), $this->findingInFoo('sensitive_data_exposure', 'Injection')]);
        $baseline = $this->writeBaseline($entries);

        self::assertSame([], $this->baselineMerger->plan($report, $baseline, false)->newFindings);
    }

    /**
     * @return iterable<string, array{list<array<string, string>>}>
     */
    public static function baselinesRepeatingAnEntry(): iterable
    {
        $entryNamingNoFile = static fn (string $type): array => ['fingerprint' => Vulnerability::fingerprintOf($type, 'src/Foo.php', 'Injection'), 'type' => $type];
        yield 'entries naming no file' => [[$entryNamingNoFile('twig_injection'), $entryNamingNoFile('sensitive_data_exposure'), $entryNamingNoFile('twig_injection')]];
        yield 'entries naming the file under another spelling' => [[self::respelledEntryInFoo('twig_injection'), self::respelledEntryInFoo('sensitive_data_exposure'), self::respelledEntryInFoo('twig_injection')]];
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_an_entry_covers_one_finding_through_its_attacker_fingerprint_and_another_under_a_former_name(): void
    {
        $report = $this->writeCompleteReportOfTheProject([
            $this->findingInFoo('sql_injection', 'Other'),
            $this->findingInFoo('xss', 'Injection'),
            $this->findingInFoo('xss', 'Injection'),
        ]);
        $baseline = $this->writeBaseline([[
            ...self::respelledEntryInFoo('twig_injection'),
            'attacker_fingerprint' => Vulnerability::fingerprintOf('sql_injection', 'src/Foo.php', 'Other'),
        ]]);

        $outcomeOf = static fn (BaselineMergePlan $baselineMergePlan): array => [
            $baselineMergePlan->prunedCount,
            \count($baselineMergePlan->keptEntries),
            array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->title, $baselineMergePlan->newFindings),
        ];

        self::assertSame(
            [[0, 1, ['Injection']], [0, 1, ['Injection']]],
            [$outcomeOf($this->baselineMerger->plan($report, $baseline, true)), $outcomeOf($this->baselineMerger->plan($report, $baseline, false))],
        );
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_entries_holding_one_finding_under_several_spellings_each_cover_one_occurrence_of_it(): void
    {
        $report = $this->writeCompleteReportOfTheProject([
            $this->findingInFoo('sql_injection', 'Injection'),
            $this->findingInFoo('sql_injection', 'Injection'),
            $this->findingInFoo('sql_injection', 'Other'),
        ]);
        $dotSlashEntry = $this->entryInFoo('sql_injection', './src/Foo.php', 'Injection');
        $backslashEntry = $this->entryInFoo('sql_injection', 'src\\Foo.php', 'Injection');
        $baseline = $this->writeBaseline([$dotSlashEntry, $backslashEntry, $dotSlashEntry]);

        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);

        self::assertSame(
            [1, [$dotSlashEntry, $backslashEntry], ['Other']],
            [
                $baselineMergePlan->prunedCount,
                array_map(static fn (BaselineEntry $baselineEntry): array|string => $baselineEntry->raw, $baselineMergePlan->keptEntries),
                array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->title, $baselineMergePlan->newFindings),
            ],
        );
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[MaximumDuration(4000)]
    public function test_the_merge_and_the_prune_match_the_pairwise_specification_on_generated_reports_and_baselines(): void
    {
        $randomizer = new Randomizer(new Xoshiro256StarStar(hash('sha256', 'audit:baseline', true)));
        $reportFindingsLoader = new ReportFindingsLoader($this->filesystem);
        $baselineFile = new Baseline($this->filesystem);

        for ($case = 0; $case < self::GENERATED_CASES; ++$case) {
            $report = $this->writeGenerated(\sprintf('report-%d.json', $case), $this->generatedReport($randomizer));
            $baseline = $this->writeGenerated(\sprintf('baseline-%d.json', $case), $this->generatedEntries($randomizer));

            foreach ([true, false] as $prune) {
                [$keptEntries, $newFindings, $prunedCount] = PairwiseBaselineMerge::plan($reportFindingsLoader->load($report), $baselineFile->entries($baseline), $prune);
                $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, $prune);

                self::assertSame(
                    [$prunedCount, $this->rawOf($keptEntries), $this->arraysOf($newFindings)],
                    [$baselineMergePlan->prunedCount, $this->rawOf($baselineMergePlan->keptEntries), $this->arraysOf($baselineMergePlan->newFindings)],
                    \sprintf('generated case %d, prune %s', $case, $prune ? 'on' : 'off'),
                );
            }
        }
    }

    /**
     * @throws MalformedBaselineFileException
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    #[MaximumDuration(4000)]
    public function test_a_report_and_a_baseline_of_thousands_of_findings_merge_in_linear_time(): void
    {
        $findings = [];
        $entries = [];
        for ($index = 0; $index < self::THOUSANDS; ++$index) {
            $findings[] = $this->findingIn(\sprintf('src/Found%d.php', $index));
            $entries[] = $this->entryInFoo('sql_injection', \sprintf('src/Accepted%d.php', $index), 'Injection');
        }

        $report = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($report, json_encode([
            'project' => '/abs/project',
            'vulnerabilities' => $findings,
            'coverage' => array_map(static fn (array $finding): array => ['stage' => 'attacker', 'file' => $finding['file'], 'status' => 'analyzed'], $findings),
            'suppressed_fingerprints' => [],
        ], \JSON_THROW_ON_ERROR));
        $baseline = $this->writeBaseline($entries);

        $startedAt = hrtime(true);
        $baselineMergePlan = $this->baselineMerger->plan($report, $baseline, true);
        $elapsedSeconds = (hrtime(true) - $startedAt) / 1_000_000_000;

        self::assertSame(
            [0, self::THOUSANDS, self::THOUSANDS],
            [$baselineMergePlan->prunedCount, \count($baselineMergePlan->keptEntries), \count($baselineMergePlan->newFindings)],
        );
        self::assertLessThan(2.0, $elapsedSeconds);
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
     * @return array{fingerprint: string, type: string, file: string, title: string, severity: string}
     */
    private function findingInFoo(string $type, string $title): array
    {
        return [
            'fingerprint' => Vulnerability::fingerprintOf($type, 'src/Foo.php', $title),
            'type' => $type,
            'file' => 'src/Foo.php',
            'title' => $title,
            'severity' => 'high',
        ];
    }

    /**
     * @return array{fingerprint: string, type: string, file: string, title: string, severity: string}
     */
    private function findingIn(string $file): array
    {
        return [
            'fingerprint' => Vulnerability::fingerprintOf('sql_injection', $file, 'Injection'),
            'type' => 'sql_injection',
            'file' => $file,
            'title' => 'Injection',
            'severity' => 'high',
        ];
    }

    /**
     * An entry a baseline written before 1.22 holds the `Injection` finding of
     * `src/Foo.php` under: the path the model echoed with a leading `./`, and
     * the type it was reported as.
     *
     * @return array<string, string>
     */
    private static function respelledEntryInFoo(string $type): array
    {
        return [
            'fingerprint' => Vulnerability::fingerprintOf($type, './src/Foo.php', 'Injection'),
            'type' => $type,
            'file' => './src/Foo.php',
            'title' => 'Injection',
            'added_at' => '2025-11-20',
        ];
    }

    /**
     * A report over two files of `/abs/project` whose findings are drawn from a
     * few types, files and titles so that they collide, sometimes listed under
     * a fingerprint of another finding, with any coverage, completeness and
     * suppressed baseline fingerprints, and written by either release.
     *
     * @return array<string, mixed>
     */
    private function generatedReport(Randomizer $randomizer): array
    {
        $findings = [];
        for ($index = $randomizer->getInt(0, 6); $index > 0; --$index) {
            [$type, $file, $title] = $this->generatedName($randomizer, false);
            [$listedType, $listedFile, $listedTitle] = 0 === $randomizer->getInt(0, 9) ? $this->generatedName($randomizer, false) : [$type, $file, $title];
            $findings[] = ['fingerprint' => Vulnerability::fingerprintOf($listedType, $listedFile, $listedTitle), 'type' => $type, 'file' => $file, 'title' => $title, 'severity' => 'high'];
        }

        $suppressedBaselineFingerprints = [];
        for ($index = $randomizer->getInt(0, 2); $index > 0; --$index) {
            $suppressedBaselineFingerprints[] = Vulnerability::fingerprintOf(...$this->generatedName($randomizer, true));
        }

        $report = [
            'complete' => 1 === $randomizer->getInt(0, 1),
            'scope' => ['since' => null, 'paths' => []],
            'vulnerabilities' => $findings,
            'coverage' => $this->generatedCoverage($randomizer),
            'suppressed_baseline_fingerprints' => $suppressedBaselineFingerprints,
        ];
        $release = $randomizer->getInt(0, 5);
        if ($release > 0) {
            $report['suppressed_fingerprints'] = [];
        }

        if ($release > 1) {
            $report['project'] = '/abs/project';
        }

        return $report;
    }

    /**
     * Each generated case gets files of its own, written in place: replacing a
     * file, as `Filesystem::dumpFile()` does through a rename, waits on the
     * disk on ext4 and made this test take seconds.
     *
     * @param array<array-key, mixed> $contents
     */
    private function writeGenerated(string $name, array $contents): string
    {
        $path = \sprintf('%s/%s', $this->tmpDir, $name);
        file_put_contents($path, json_encode($contents, \JSON_THROW_ON_ERROR));

        return $path;
    }

    /**
     * @return list<array{stage: string, file: string, status: string}>
     */
    private function generatedCoverage(Randomizer $randomizer): array
    {
        $coverage = [];
        foreach (self::GENERATED_FILES as $file) {
            $status = self::GENERATED_STATUSES[$randomizer->getInt(0, \count(self::GENERATED_STATUSES) - 1)];
            if (null !== $status) {
                $coverage[] = ['stage' => 'attacker', 'file' => $file, 'status' => $status];
            }
        }

        return $coverage;
    }

    /**
     * Entries naming a finding under any spelling of its file and any type it
     * was reported as, at times under a fingerprint of another finding, with or
     * without an attacker fingerprint or a file, or as a bare fingerprint.
     *
     * @return list<array<string, string>|string>
     */
    private function generatedEntries(Randomizer $randomizer): array
    {
        $entries = [];
        for ($index = $randomizer->getInt(0, 6); $index > 0; --$index) {
            [$type, $file, $title] = $this->generatedName($randomizer, true);
            $fingerprint = Vulnerability::fingerprintOf(...(0 === $randomizer->getInt(0, 3) ? $this->generatedName($randomizer, true) : [$type, $file, $title]));
            $entry = ['fingerprint' => $fingerprint, 'type' => $type, 'file' => $file, 'title' => $title];
            if (0 === $randomizer->getInt(0, 3)) {
                $entry['attacker_fingerprint'] = Vulnerability::fingerprintOf(...$this->generatedName($randomizer, false));
            }

            $entries[] = match ($randomizer->getInt(0, 7)) {
                0 => $fingerprint,
                1 => array_diff_key($entry, ['file' => true]),
                default => $entry,
            };
        }

        return $entries;
    }

    /**
     * @return array{string, string, string}
     */
    private function generatedName(Randomizer $randomizer, bool $respelled): array
    {
        $file = self::GENERATED_FILES[$randomizer->getInt(0, \count(self::GENERATED_FILES) - 1)];
        $spellings = [$file, './'.$file, '/'.$file, str_replace('/', '\\', $file), '/abs/project/'.$file, 'lib/'.$file];

        return [
            self::GENERATED_TYPES[$randomizer->getInt(0, \count(self::GENERATED_TYPES) - 1)],
            $respelled ? $spellings[$randomizer->getInt(0, \count($spellings) - 1)] : $file,
            self::GENERATED_TITLES[$randomizer->getInt(0, \count(self::GENERATED_TITLES) - 1)],
        ];
    }

    /**
     * @param list<BaselineEntry> $entries
     *
     * @return list<array<array-key, mixed>|string>
     */
    private function rawOf(array $entries): array
    {
        return array_map(static fn (BaselineEntry $baselineEntry): array|string => $baselineEntry->raw, $entries);
    }

    /**
     * @param list<DiffFinding> $findings
     *
     * @return list<array{fingerprint: string, type: string, file: string, title: string, severity: string}>
     */
    private function arraysOf(array $findings): array
    {
        return array_map(static fn (DiffFinding $diffFinding): array => $diffFinding->toArray(), $findings);
    }

    /**
     * @return array<string, string>
     */
    private function entryInFoo(string $type, string $file, string $title): array
    {
        return [
            'fingerprint' => Vulnerability::fingerprintOf($type, $file, $title),
            'type' => $type,
            'file' => $file,
            'title' => $title,
            'added_at' => '2025-11-20',
        ];
    }

    /**
     * A complete run over the whole project at `/abs/project` whose attacker
     * analyzed `src/Foo.php`, so the absence of a finding there is proven,
     * written since reports list `suppressed_fingerprints`.
     *
     * @param list<array<string, string>> $vulnerabilities
     */
    private function writeCompleteReportOfTheProject(array $vulnerabilities): string
    {
        $path = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($path, json_encode([
            'project' => '/abs/project',
            'complete' => true,
            'scope' => ['since' => null, 'paths' => []],
            'vulnerabilities' => $vulnerabilities,
            'coverage' => [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'analyzed']],
            'suppressed_fingerprints' => [],
        ], \JSON_THROW_ON_ERROR));

        return $path;
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
     * The ledger says the run analyzed `src/Foo.php`, so a finding missing from
     * the report would be gone for good were it not listed as suppressed.
     *
     * @param list<array<string, string>> $vulnerabilities
     * @param list<string>|null           $suppressedBaseline
     */
    private function writeReportWithSuppressed(array $vulnerabilities, mixed $suppressed, ?array $suppressedBaseline = null): string
    {
        $path = $this->tmpDir.'/report.json';
        $this->filesystem->dumpFile($path, json_encode([
            'vulnerabilities' => $vulnerabilities,
            'coverage' => [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'analyzed']],
            'suppressed_fingerprints' => $suppressed,
            ...null === $suppressedBaseline ? [] : ['suppressed_baseline_fingerprints' => $suppressedBaseline],
        ], \JSON_THROW_ON_ERROR));

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
