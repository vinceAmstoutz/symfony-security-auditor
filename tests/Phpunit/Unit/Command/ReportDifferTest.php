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
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedReportFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ReportFileNotReadableException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportDiffer;

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

        $reportDiff = (new ReportDiffer($this->filesystem))->diff($previous, $current);

        self::assertCount(1, $reportDiff->newFindings);
        self::assertSame('SQL Injection', $reportDiff->newFindings[0]->title);
        self::assertSame([], $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->persistingFindings);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_classifies_a_finding_only_in_the_previous_report_as_fixed(): void
    {
        $previous = $this->writeReport('previous.json', [$this->vulnerability('SQL Injection')]);
        $current = $this->writeReport('current.json', []);

        $reportDiff = (new ReportDiffer($this->filesystem))->diff($previous, $current);

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

        $reportDiff = (new ReportDiffer($this->filesystem))->diff($previous, $current);

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

        $reportDiff = (new ReportDiffer($this->filesystem))->diff($previous, $current);

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

        $reportDiff = (new ReportDiffer($this->filesystem))->diff($previous, $current);

        self::assertSame([], $reportDiff->newFindings);
        self::assertSame([], $reportDiff->fixedFindings);
        self::assertSame([], $reportDiff->persistingFindings);
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

        $reportDiff = (new ReportDiffer($this->filesystem))->diff($previous, $current);

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

        (new ReportDiffer($this->filesystem))->diff($this->tmpDir.'/absent.json', $current);
    }

    /**
     * @throws ReportFileNotReadableException
     * @throws MalformedReportFileException
     */
    public function test_diff_throws_when_a_report_path_exists_but_cannot_be_read_as_a_file(): void
    {
        $current = $this->writeReport('current.json', []);

        try {
            (new ReportDiffer($this->filesystem))->diff($this->tmpDir, $current);
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

        (new ReportDiffer($this->filesystem))->diff($previous, $current);
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

        (new ReportDiffer($this->filesystem))->diff($previous, $current);
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

        (new ReportDiffer($this->filesystem))->diff($previous, $current);
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

        (new ReportDiffer($this->filesystem))->diff($previous, $current);
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

        (new ReportDiffer($this->filesystem))->diff($previous, $current);
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
    private function vulnerability(string $title): array
    {
        return [
            'type' => 'sql_injection',
            'file' => 'src/Foo.php',
            'title' => $title,
            'severity' => 'high',
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
}
