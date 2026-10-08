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
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Command\DiffFinding;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportDiffer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportFindingsLoader;

final class ReportDifferTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/report_differ_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_classifies_a_finding_only_in_the_current_report_as_new(): void
    {
        $previous = $this->writeReport('previous.json', []);
        $current = $this->writeReport('current.json', [$this->vulnerability('SQL Injection')]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->newFindings);
        self::assertSame('SQL Injection', $reportDiff->newFindings[0]->title);
        self::assertSame([], $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->persistingFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_reports_every_distinct_new_fingerprint_not_only_the_last(): void
    {
        $previous = $this->writeReport('previous.json', []);
        $current = $this->writeReport('current.json', [
            $this->vulnerability('SQL Injection'),
            $this->vulnerability('Mass Assignment'),
        ]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(2, $reportDiff->newFindings);
        $titles = array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->title, $reportDiff->newFindings);
        self::assertContains('SQL Injection', $titles);
        self::assertContains('Mass Assignment', $titles);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_classifies_a_finding_only_in_the_previous_report_as_fixed(): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeReport('current.json', []);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->newFindings);
        self::assertCount(1, $reportDiff->fixedFindings);
        self::assertSame('SQL Injection', $reportDiff->fixedFindings[0]->title);
        self::assertSame([], $reportDiff->persistingFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_classifies_a_finding_in_both_reports_as_persisting(): void
    {
        $vulnerability = $this->vulnerability('SQL Injection');
        $previous = $this->writeReport('previous.json', [$vulnerability]);
        $current = $this->writeReport('current.json', [$vulnerability]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->newFindings);
        self::assertSame([], $reportDiff->fixedFindings);
        self::assertCount(1, $reportDiff->persistingFindings);
        self::assertSame('SQL Injection', $reportDiff->persistingFindings[0]->title);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_of_two_identical_reports_yields_no_new_or_fixed_findings(): void
    {
        $vulnerability = $this->vulnerability('SQL Injection');
        $previous = $this->writeReport('previous.json', [$vulnerability]);
        $current = $this->writeReport('current.json', [$vulnerability]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->newFindings);
        self::assertSame([], $reportDiff->fixedFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_of_two_empty_reports_yields_no_findings_in_any_bucket(): void
    {
        $previous = $this->writeReport('previous.json', []);
        $current = $this->writeReport('current.json', []);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->newFindings);
        self::assertSame([], $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->persistingFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_treats_an_extra_current_finding_sharing_a_fingerprint_as_new_not_hidden(): void
    {
        $collidingLow = $this->vulnerability('SQL Injection', 'low');
        $collidingHigh = $this->vulnerability('SQL Injection', 'high');
        $previous = $this->writeReport('previous.json', [$collidingLow]);
        $current = $this->writeReport('current.json', [$collidingLow, $collidingHigh]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->newFindings);
        self::assertCount(1, $reportDiff->persistingFindings);
        self::assertSame([], $reportDiff->fixedFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_treats_an_extra_previous_finding_sharing_a_fingerprint_as_fixed_not_hidden(): void
    {
        $collidingLow = $this->vulnerability('SQL Injection', 'low');
        $collidingHigh = $this->vulnerability('SQL Injection', 'high');
        $previous = $this->writeReport('previous.json', [$collidingLow, $collidingHigh]);
        $current = $this->writeReport('current.json', [$collidingLow]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->newFindings);
        self::assertCount(1, $reportDiff->fixedFindings);
        self::assertCount(1, $reportDiff->persistingFindings);
    }

    /**
     * Several findings sharing one fingerprint on both sides but in different
     * counts are paired off 1:1 in encounter order: the current report's first
     * N (N = the previous count) persist, its remainder is new, and any
     * previous excess is fixed. Pins the slice offset (from the front, not the
     * back) and length so each bucket keeps exactly the entries it should, in
     * order — not just the right count.
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_pairs_off_findings_sharing_one_fingerprint_by_count_and_encounter_order(): void
    {
        $previous = $this->writeReport('previous.json', [
            $this->vulnerability('SQL Injection', 'low'),
            $this->vulnerability('SQL Injection', 'medium'),
        ]);
        $current = $this->writeReport('current.json', [
            $this->vulnerability('SQL Injection', 'low'),
            $this->vulnerability('SQL Injection', 'medium'),
            $this->vulnerability('SQL Injection', 'high'),
            $this->vulnerability('SQL Injection', 'critical'),
        ]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame(['low', 'medium'], $this->severitiesOf($reportDiff->persistingFindings));
        self::assertSame(['high', 'critical'], $this->severitiesOf($reportDiff->newFindings));
        self::assertSame([], $reportDiff->fixedFindings);
    }

    /**
     * @param list<DiffFinding> $findings
     *
     * @return list<string>
     */
    private function severitiesOf(array $findings): array
    {
        return array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->severity, $findings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_recomputes_the_fingerprint_when_the_key_is_absent(): void
    {
        $vulnerability = $this->vulnerability('SQL Injection');
        unset($vulnerability['fingerprint']);
        $previous = $this->writeReport('previous.json', [$vulnerability]);
        $current = $this->writeReport('current.json', [$vulnerability]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->persistingFindings);
        self::assertSame(
            Vulnerability::fingerprintOf('sql_injection', 'src/Foo.php', 'SQL Injection'),
            $reportDiff->persistingFindings[0]->fingerprint,
        );
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_throws_when_the_previous_report_file_is_missing(): void
    {
        $current = $this->writeReport('current.json', []);

        $this->expectException(ReportFileNotReadableException::class);

        (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($this->tmpDir.'/absent.json', $current);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_throws_when_a_report_path_exists_but_cannot_be_read_as_a_file(): void
    {
        $current = $this->writeReport('current.json', []);

        try {
            (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($this->tmpDir, $current);
            self::fail('Expected a ReportFileNotReadableException for a directory path.');
        } catch (ReportFileNotReadableException $reportFileNotReadableException) {
            self::assertInstanceOf(IOException::class, $reportFileNotReadableException->getPrevious());
        }
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_throws_when_a_report_is_not_valid_json(): void
    {
        $previous = $this->tmpDir.'/broken.json';
        $this->filesystem->dumpFile($previous, '{not json');
        $current = $this->writeReport('current.json', []);

        $this->expectException(MalformedReportFileException::class);

        (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_throws_when_the_report_has_no_vulnerabilities_array(): void
    {
        $previous = $this->tmpDir.'/no-vulns.json';
        $this->filesystem->dumpFile($previous, '{"audit_id": "x"}');
        $current = $this->writeReport('current.json', []);

        $this->expectException(MalformedReportFileException::class);

        (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_throws_when_the_report_top_level_is_not_a_json_object(): void
    {
        $previous = $this->tmpDir.'/scalar.json';
        $this->filesystem->dumpFile($previous, '42');
        $current = $this->writeReport('current.json', []);

        $this->expectException(MalformedReportFileException::class);

        (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_throws_when_a_vulnerability_entry_is_not_an_object(): void
    {
        $previous = $this->tmpDir.'/bad-entry.json';
        $this->filesystem->dumpFile($previous, '{"vulnerabilities": [42]}');
        $current = $this->writeReport('current.json', []);

        $this->expectException(MalformedReportFileException::class);
        $this->expectExceptionMessage('has a vulnerability entry at index 0 that is not a JSON object');

        (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_reports_the_actual_position_of_a_bad_entry_when_vulnerabilities_is_a_json_object_with_non_numeric_keys(): void
    {
        $previous = $this->tmpDir.'/object-entries.json';
        $this->filesystem->dumpFile(
            $previous,
            '{"vulnerabilities": {"alpha": {"type": "sql_injection", "file": "src/Foo.php", "title": "SQL Injection", "severity": "high"}, "beta": 42}}',
        );
        $current = $this->writeReport('current.json', []);

        $this->expectException(MalformedReportFileException::class);
        $this->expectExceptionMessage('has a vulnerability entry at index 1 that is not a JSON object');

        (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);
    }

    /**
     * @param array<string, string> $vulnerability
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    #[DataProvider('vulnerabilityEntriesMissingARequiredFieldCases')]
    public function test_diff_throws_when_a_vulnerability_entry_is_missing_a_required_field(array $vulnerability): void
    {
        $previous = $this->tmpDir.'/missing-field.json';
        $this->filesystem->dumpFile($previous, json_encode(['vulnerabilities' => [$vulnerability]], \JSON_THROW_ON_ERROR));
        $current = $this->writeReport('current.json', []);

        $this->expectException(MalformedReportFileException::class);

        (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function vulnerabilityEntriesMissingARequiredFieldCases(): iterable
    {
        $complete = ['type' => 'sql_injection', 'file' => 'src/Foo.php', 'title' => 'SQL Injection', 'severity' => 'high'];

        yield 'missing type' => [self::withoutField($complete, 'type')];
        yield 'missing file' => [self::withoutField($complete, 'file')];
        yield 'missing title' => [self::withoutField($complete, 'title')];
        yield 'missing severity' => [self::withoutField($complete, 'severity')];
    }

    /**
     * @param array<string, string> $vulnerability
     *
     * @return array<string, string>
     */
    private static function withoutField(array $vulnerability, string $field): array
    {
        unset($vulnerability[$field]);

        return $vulnerability;
    }

    /**
     * @return array{type: string, file: string, title: string, severity: string, fingerprint: string}
     */
    private function vulnerability(string $title, string $severity = 'high'): array
    {
        return [
            'type' => 'sql_injection',
            'file' => 'src/Foo.php',
            'title' => $title,
            'severity' => $severity,
            'fingerprint' => Vulnerability::fingerprintOf('sql_injection', 'src/Foo.php', $title),
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

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_keeps_a_finding_gone_from_a_file_the_current_run_could_not_analyze_apart_from_the_fixed_ones(): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeReportWithCoverage('current.json', [], [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'errored']]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->fixedFindings);
        self::assertCount(1, $reportDiff->unverifiedFindings);
        self::assertSame('SQL Injection', $reportDiff->unverifiedFindings[0]->title);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_calls_a_finding_fixed_when_the_current_run_analyzed_its_file(): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeReportWithCoverage('current.json', [], [
            ['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'errored'],
            ['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'analyzed'],
        ]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->unverifiedFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_only_reads_the_coverage_of_the_current_report(): void
    {
        $previous = $this->writeReportWithCoverage('previous.json', [$this->vulnerability('SQL Injection')], [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'errored']]);
        $current = $this->writeReport('current.json', []);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->unverifiedFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    #[DataProvider('coverageLedgersNamingNoFile')]
    public function test_diff_treats_a_report_without_a_readable_coverage_ledger_as_complete(mixed $coverage): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeReportWithCoverage('current.json', [], $coverage);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->unverifiedFindings);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function coverageLedgersNamingNoFile(): iterable
    {
        yield 'a ledger that is not a list' => ['errored'];
        yield 'no ledger at all' => [null];
    }

    /**
     * A ledger says which files the later run looked at. A finding that
     * disappeared from any other file — one the lean pre-scan skipped, one
     * outside a `--since` or `--path` scope, one the ledger does not name in a
     * readable entry — was never looked at, so nothing says it is fixed.
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    #[DataProvider('ledgersThatNeverSayTheFileWasAnalyzed')]
    public function test_diff_keeps_a_finding_apart_when_the_current_ledger_never_says_its_file_was_analyzed(mixed $coverage): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeReportWithCoverage('current.json', [], $coverage);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->fixedFindings);
        self::assertCount(1, $reportDiff->unverifiedFindings);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function ledgersThatNeverSayTheFileWasAnalyzed(): iterable
    {
        yield 'a file the lean pre-scan skipped' => [[['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'skipped']]];
        yield 'a file outside the scope of the run' => [[['stage' => 'attacker', 'file' => 'src/Bar.php', 'status' => 'analyzed']]];
        yield 'a run with nothing in scope' => [[]];
        yield 'a file only another stage claims to have analyzed' => [[['stage' => 'reviewer', 'file' => 'src/Foo.php', 'status' => 'analyzed']]];
        yield 'an entry that is not an object' => [['src/Foo.php']];
        yield 'an entry missing its status' => [[['stage' => 'attacker', 'file' => 'src/Foo.php']]];
        yield 'an entry whose file is not a string' => [[['stage' => 'attacker', 'file' => 42, 'status' => 'analyzed']]];
        yield 'an entry whose stage is not a string' => [[['stage' => null, 'file' => 'src/Foo.php', 'status' => 'analyzed']]];
        yield 'an entry whose status is not a string' => [[['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => true]]];
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_calls_a_finding_fixed_when_the_current_run_served_its_file_from_the_cache(): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeReportWithCoverage('current.json', [], [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'cached']]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->unverifiedFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_calls_a_finding_fixed_when_the_ledger_names_its_analyzed_file_with_a_leading_dot_slash(): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeReportWithCoverage('current.json', [], [['stage' => 'attacker', 'file' => './src/Foo.php', 'status' => 'analyzed']]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->unverifiedFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_calls_a_finding_echoed_with_a_leading_dot_slash_fixed_when_the_current_run_analyzed_its_file(): void
    {
        $echoed = ['type' => 'sql_injection', 'file' => './src/Foo.php', 'title' => 'SQL Injection', 'severity' => 'high', 'fingerprint' => Vulnerability::fingerprintOf('sql_injection', './src/Foo.php', 'SQL Injection')];
        $previous = $this->writeReport('previous.json', [$echoed]);
        $current = $this->writeReportWithCoverage('current.json', [], [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'analyzed']]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->unverifiedFindings);
    }

    /**
     * A file a complete run over the whole history never listed, inside the
     * scope it scanned, is gone: deleted, or no longer in the scan. A finding
     * that disappeared with it is fixed.
     *
     * @param array<string, mixed> $scope
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    #[DataProvider('scopesHoldingTheFile')]
    public function test_diff_calls_a_finding_fixed_when_a_complete_run_over_its_scope_no_longer_lists_its_file(array $scope): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeScopedReport('current.json', ['complete' => true, 'scope' => $scope]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertCount(1, $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->unverifiedFindings);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function scopesHoldingTheFile(): iterable
    {
        yield 'the whole project' => [['since' => null, 'paths' => []]];
        yield 'a --path the file lives under' => [['since' => null, 'paths' => ['src']]];
        yield 'a --path list holding an entry that is not a string' => [['since' => null, 'paths' => [42, 'src']]];
    }

    /**
     * @param array<string, mixed> $report
     *
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    #[DataProvider('reportsThatCannotSayTheFileIsGone')]
    public function test_diff_keeps_a_finding_apart_when_the_current_report_cannot_say_its_file_is_gone(array $report): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeScopedReport('current.json', $report);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->fixedFindings);
        self::assertCount(1, $reportDiff->unverifiedFindings);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function reportsThatCannotSayTheFileIsGone(): iterable
    {
        $fullScope = ['since' => null, 'paths' => []];
        $anotherFileAnalyzed = ['stage' => 'attacker', 'file' => 'src/Other.php', 'status' => 'analyzed'];

        yield 'an incomplete run' => [['complete' => false, 'scope' => $fullScope]];
        yield 'a report that does not say it is complete' => [['scope' => $fullScope]];
        yield 'a complete flag that is not a boolean' => [['complete' => 'yes', 'scope' => $fullScope]];
        yield 'a --since run' => [['complete' => true, 'scope' => ['since' => 'main', 'paths' => []]]];
        yield 'a file outside the --path scope' => [['complete' => true, 'scope' => ['since' => null, 'paths' => ['src/Controller']]]];
        yield 'a file the lean pre-scan skipped' => [['complete' => true, 'scope' => $fullScope, 'coverage' => [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'skipped'], $anotherFileAnalyzed]]];
        yield 'a file the ledger lists under the path the attacker echoed' => [['complete' => true, 'scope' => $fullScope, 'coverage' => [['stage' => 'attacker', 'file' => './src/Foo.php', 'status' => 'skipped'], $anotherFileAnalyzed]]];
        yield 'a file the scan left out for being over the size limit' => [['complete' => false, 'scope' => $fullScope, 'coverage' => [['stage' => 'scan', 'file' => 'src/Foo.php', 'status' => 'errored'], $anotherFileAnalyzed]]];
        yield 'a file a host stage listed' => [['complete' => true, 'scope' => $fullScope, 'coverage' => [['stage' => 'secret_scrubbing', 'file' => 'src/Foo.php', 'status' => 'analyzed'], $anotherFileAnalyzed]]];
        yield 'a report written before the scope existed' => [['complete' => true]];
        yield 'a scope that is not an object' => [['complete' => true, 'scope' => 'everything']];
        yield 'a scope that does not say whether it ran with --since' => [['complete' => true, 'scope' => ['paths' => []]]];
        yield 'a scope whose paths are not a list' => [['complete' => true, 'scope' => ['since' => null, 'paths' => 'src']]];
        yield 'a run whose scan found no file' => [['complete' => true, 'files_scanned' => 0, 'scope' => $fullScope, 'coverage' => []]];
        yield 'a run that analyzed no file' => [['complete' => true, 'scope' => $fullScope, 'coverage' => [['stage' => 'attacker', 'file' => 'src/Other.php', 'status' => 'skipped']]]];
    }

    /**
     * @param array<string, mixed> $report the report's `complete`, `scope` and
     *                                     `coverage` keys; the coverage lists
     *                                     another, analyzed file by default
     */
    private function writeScopedReport(string $filename, array $report): string
    {
        $path = $this->tmpDir.'/'.$filename;
        $this->filesystem->dumpFile($path, json_encode([
            'vulnerabilities' => [],
            'coverage' => [['stage' => 'attacker', 'file' => 'src/Other.php', 'status' => 'analyzed']],
            ...$report,
        ], \JSON_THROW_ON_ERROR));

        return $path;
    }

    /**
     * @param list<array<string, string>> $vulnerabilities
     */
    private function writeReportWithCoverage(string $filename, array $vulnerabilities, mixed $coverage): string
    {
        $path = $this->tmpDir.'/'.$filename;
        $this->filesystem->dumpFile($path, json_encode(['vulnerabilities' => $vulnerabilities, 'coverage' => $coverage], \JSON_THROW_ON_ERROR));

        return $path;
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_keeps_sorting_the_findings_that_disappeared_after_an_unverified_one(): void
    {
        $inUnanalyzedFile = $this->vulnerability('SQL Injection');
        $inAnalyzedFile = [
            'type' => 'mass_assignment',
            'file' => 'src/Bar.php',
            'title' => 'Mass Assignment',
            'severity' => 'medium',
            'fingerprint' => Vulnerability::fingerprintOf('mass_assignment', 'src/Bar.php', 'Mass Assignment'),
        ];
        $previous = $this->writeReport('previous.json', [$inUnanalyzedFile, $inAnalyzedFile]);
        $current = $this->writeReportWithCoverage('current.json', [], [
            ['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'errored'],
            ['stage' => 'attacker', 'file' => 'src/Bar.php', 'status' => 'analyzed'],
        ]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame(['SQL Injection'], array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->title, $reportDiff->unverifiedFindings));
        self::assertSame(['Mass Assignment'], array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->title, $reportDiff->fixedFindings));
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_keeps_a_finding_echoed_with_a_leading_dot_slash_apart_when_its_file_could_not_be_analyzed(): void
    {
        $echoed = ['type' => 'sql_injection', 'file' => './src/Foo.php', 'title' => 'SQL Injection', 'severity' => 'high', 'fingerprint' => Vulnerability::fingerprintOf('sql_injection', './src/Foo.php', 'SQL Injection')];
        $previous = $this->writeReport('previous.json', [$echoed]);
        $current = $this->writeReportWithCoverage('current.json', [], [['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'errored']]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->fixedFindings);
        self::assertSame(['./src/Foo.php'], array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->file, $reportDiff->unverifiedFindings));
    }

    /**
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_diff_keeps_a_finding_apart_when_the_reviewer_failed_on_it_under_the_path_the_attacker_echoed(): void
    {
        $echoed = ['type' => 'sql_injection', 'file' => './src/Foo.php', 'title' => 'SQL Injection', 'severity' => 'high', 'fingerprint' => Vulnerability::fingerprintOf('sql_injection', './src/Foo.php', 'SQL Injection')];
        $previous = $this->writeReport('previous.json', [$echoed]);
        $current = $this->writeReportWithCoverage('current.json', [], [['stage' => 'reviewer', 'file' => './src/Foo.php', 'status' => 'errored']]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->fixedFindings);
        self::assertSame(['./src/Foo.php'], array_map(static fn (DiffFinding $diffFinding): string => $diffFinding->file, $reportDiff->unverifiedFindings));
    }

    /**
     * @throws MalformedReportFileException
     * @throws ReportFileNotReadableException
     */
    public function test_diff_keeps_a_plain_path_finding_apart_when_the_reviewer_failed_on_it_under_an_echoed_path(): void
    {
        $plain = ['type' => 'sql_injection', 'file' => 'src/Foo.php', 'title' => 'SQL Injection', 'severity' => 'high', 'fingerprint' => Vulnerability::fingerprintOf('sql_injection', 'src/Foo.php', 'SQL Injection')];
        $previous = $this->writeReport('previous.json', [$plain]);
        $current = $this->writeReportWithCoverage('current.json', [], [
            ['stage' => 'attacker', 'file' => 'src/Foo.php', 'status' => 'analyzed'],
            ['stage' => 'reviewer', 'file' => './src/Foo.php', 'status' => 'errored'],
        ]);

        $reportDiff = (new ReportDiffer(new ReportFindingsLoader($this->filesystem)))->diff($previous, $current);

        self::assertSame([], $reportDiff->fixedFindings);
        self::assertCount(1, $reportDiff->unverifiedFindings);
    }
}
