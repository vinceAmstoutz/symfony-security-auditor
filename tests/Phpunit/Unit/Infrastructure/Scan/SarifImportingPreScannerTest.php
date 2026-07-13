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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\MalformedSarifFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\SarifFileNotReadableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SarifImportingPreScanner;

final class SarifImportingPreScannerTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/sarif_import_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_a_sarif_result_becomes_a_marker_at_its_file_line_and_rule(): void
    {
        $sarif = $this->writeSarif([$this->sarifRun('Psalm', [
            $this->sarifResult('TaintedSql', 'Detected tainted SQL', 'src/Repository/UserRepository.php', 42),
        ])]);

        $markers = $this->scanner([$sarif])->scan([$this->projectFile('src/Repository/UserRepository.php')]);

        self::assertCount(1, $markers);
        self::assertSame(
            ['src/Repository/UserRepository.php', 42, 'sarif:Psalm:TaintedSql', 'Detected tainted SQL'],
            [$markers[0]->filePath(), $markers[0]->line(), $markers[0]->pattern(), $markers[0]->description()],
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_imported_markers_are_merged_after_the_inner_scanner_markers(): void
    {
        $sarif = $this->writeSarif([$this->sarifRun('Psalm', [
            $this->sarifResult('TaintedSql', 'Detected tainted SQL', 'src/A.php', 3),
        ])]);
        $regexStaticPreScanner = new RegexStaticPreScanner([
            'php' => ['inner_marker' => ['regex' => '/legacyQuery/', 'description' => 'test']],
        ]);
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', "<?php\nlegacyQuery(\$input);\n");

        $markers = $this->scanner([$sarif], $regexStaticPreScanner)->scan([$projectFile]);

        self::assertSame(
            ['inner_marker', 'sarif:Psalm:TaintedSql'],
            array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_a_result_pointing_outside_the_scan_surface_is_dropped(): void
    {
        $sarif = $this->writeSarif([$this->sarifRun('Psalm', [
            $this->sarifResult('TaintedSql', 'Detected tainted SQL', 'legacy/Outside.php', 3),
        ])]);

        self::assertSame([], $this->scanner([$sarif])->scan([$this->projectFile('src/A.php')]));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    #[DataProvider('equivalentUriSpellings')]
    public function test_equivalent_uri_spellings_match_the_scanned_file(string $uri): void
    {
        $sarif = $this->writeSarif([$this->sarifRun('Psalm', [
            $this->sarifResult('TaintedSql', 'Detected tainted SQL', $uri, 3),
        ])]);

        $markers = $this->scanner([$sarif])->scan([$this->projectFile('src/A.php')]);

        self::assertCount(1, $markers);
        self::assertSame('src/A.php', $markers[0]->filePath());
    }

    /** @return iterable<string, array{string}> */
    public static function equivalentUriSpellings(): iterable
    {
        yield 'plain relative' => ['src/A.php'];
        yield 'dot-slash relative' => ['./src/A.php'];
        yield 'file scheme absolute' => ['file:///app/src/A.php'];
        yield 'absolute under project root' => ['/app/src/A.php'];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_a_missing_or_non_positive_start_line_clamps_to_line_one(): void
    {
        $result = $this->sarifResult('TaintedSql', 'Detected tainted SQL', 'src/A.php', 0);
        $sarif = $this->writeSarif([$this->sarifRun('Psalm', [$result])]);

        $markers = $this->scanner([$sarif])->scan([$this->projectFile('src/A.php')]);

        self::assertSame(1, $markers[0]->line());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_the_message_falls_back_to_the_rule_id_and_the_rule_to_a_generic_label(): void
    {
        $bareResult = [
            'locations' => [['physicalLocation' => ['artifactLocation' => ['uri' => 'src/A.php']]]],
        ];
        $sarif = $this->writeSarif([$this->sarifRun('Psalm', [$bareResult])]);

        $markers = $this->scanner([$sarif])->scan([$this->projectFile('src/A.php')]);

        self::assertSame(['sarif:Psalm:result', 'result'], [$markers[0]->pattern(), $markers[0]->description()]);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_a_result_without_a_location_uri_is_skipped(): void
    {
        $sarif = $this->writeSarif([$this->sarifRun('Psalm', [['ruleId' => 'NoLocation', 'message' => ['text' => 'no location']]])]);

        self::assertSame([], $this->scanner([$sarif])->scan([$this->projectFile('src/A.php')]));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_a_run_without_a_tool_name_labels_markers_with_a_generic_tool(): void
    {
        $run = ['results' => [$this->sarifResult('R1', 'msg', 'src/A.php', 2)]];
        $sarif = $this->writeSarif([$run]);

        $markers = $this->scanner([$sarif])->scan([$this->projectFile('src/A.php')]);

        self::assertSame('sarif:sarif:R1', $markers[0]->pattern());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_markers_from_every_configured_sarif_file_are_imported(): void
    {
        $first = $this->writeSarif([$this->sarifRun('Psalm', [$this->sarifResult('R1', 'a', 'src/A.php', 1)])], 'first.sarif');
        $second = $this->writeSarif([$this->sarifRun('PHPStan', [$this->sarifResult('R2', 'b', 'src/A.php', 2)])], 'second.sarif');

        $markers = $this->scanner([$first, $second])->scan([$this->projectFile('src/A.php')]);

        self::assertSame(
            ['sarif:Psalm:R1', 'sarif:PHPStan:R2'],
            array_map(static fn (RiskMarker $riskMarker): string => $riskMarker->pattern(), $markers),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_a_relative_sarif_path_resolves_against_the_audited_project_root(): void
    {
        $this->writeSarif([$this->sarifRun('Psalm', [$this->sarifResult('R1', 'a', 'src/A.php', 1)])], 'report.sarif');
        $sarifImportingPreScanner = new SarifImportingPreScanner(
            new RegexStaticPreScanner(),
            ['report.sarif'],
            $this->filesystem,
            new AuditedProjectPathHolder($this->tmpDir),
        );

        $markers = $sarifImportingPreScanner->scan([$this->projectFile('src/A.php')]);

        self::assertCount(1, $markers);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_a_missing_sarif_file_aborts_with_a_clear_error(): void
    {
        $this->expectException(SarifFileNotReadableException::class);
        $this->expectExceptionMessage('does not exist or is not readable');

        $this->scanner([$this->tmpDir.'/absent.sarif'])->scan([$this->projectFile('src/A.php')]);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_an_invalid_json_sarif_file_aborts_with_a_clear_error(): void
    {
        $path = $this->tmpDir.'/broken.sarif';
        $this->filesystem->dumpFile($path, '{not json');

        $this->expectException(MalformedSarifFileException::class);
        $this->expectExceptionMessage('is not valid JSON');

        $this->scanner([$path])->scan([$this->projectFile('src/A.php')]);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    #[DataProvider('runsMissingDocuments')]
    public function test_a_json_document_without_a_runs_array_aborts_with_a_clear_error(string $json): void
    {
        $path = $this->tmpDir.'/noruns.sarif';
        $this->filesystem->dumpFile($path, $json);

        $this->expectException(MalformedSarifFileException::class);
        $this->expectExceptionMessage('must be a JSON object with a "runs" array');

        $this->scanner([$path])->scan([$this->projectFile('src/A.php')]);
    }

    /** @return iterable<string, array{string}> */
    public static function runsMissingDocuments(): iterable
    {
        yield 'object without runs' => ['{"version": "2.1.0"}'];
        yield 'bare scalar' => ['42'];
        yield 'runs is not an array' => ['{"runs": "nope"}'];
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_non_object_runs_and_results_entries_are_skipped(): void
    {
        $run = $this->sarifRun('Psalm', ['garbage', $this->sarifResult('R1', 'a', 'src/A.php', 1)]);
        $sarif = $this->writeSarif(['garbage', $run]);

        $markers = $this->scanner([$sarif])->scan([$this->projectFile('src/A.php')]);

        self::assertCount(1, $markers);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_a_run_whose_results_key_is_not_an_array_yields_no_markers(): void
    {
        $sarif = $this->writeSarif([['tool' => ['driver' => ['name' => 'Psalm']], 'results' => 'nope']]);

        self::assertSame([], $this->scanner([$sarif])->scan([$this->projectFile('src/A.php')]));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_a_whitespace_only_message_falls_back_to_the_rule_id(): void
    {
        $result = [
            'ruleId' => 'R9',
            'message' => ['text' => '   '],
            'locations' => [['physicalLocation' => ['artifactLocation' => ['uri' => 'src/A.php']]]],
        ];
        $sarif = $this->writeSarif([$this->sarifRun('Psalm', [$result])]);

        $markers = $this->scanner([$sarif])->scan([$this->projectFile('src/A.php')]);

        self::assertSame('R9', $markers[0]->description());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    public function test_an_unreadable_sarif_file_aborts_with_a_clear_error(): void
    {
        $filesystem = $this->createMock(Filesystem::class);
        $filesystem->method('exists')->willReturn(true);
        $filesystem->expects(self::once())
            ->method('readFile')
            ->willThrowException(new IOException('permission denied'));
        $sarifImportingPreScanner = new SarifImportingPreScanner(
            new RegexStaticPreScanner(),
            ['/reports/psalm.sarif'],
            $filesystem,
            new AuditedProjectPathHolder('/app'),
        );

        $this->expectException(SarifFileNotReadableException::class);
        $this->expectExceptionMessage('does not exist or is not readable');

        $sarifImportingPreScanner->scan([$this->projectFile('src/A.php')]);
    }

    /**
     * @param list<string> $sarifPaths
     */
    private function scanner(array $sarifPaths, ?RegexStaticPreScanner $regexStaticPreScanner = null): SarifImportingPreScanner
    {
        return new SarifImportingPreScanner(
            $regexStaticPreScanner ?? new RegexStaticPreScanner(),
            $sarifPaths,
            $this->filesystem,
            new AuditedProjectPathHolder('/app'),
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function projectFile(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/app/'.$relativePath, "<?php\n");
    }

    /**
     * @param list<mixed> $results
     *
     * @return array<string, mixed>
     */
    private function sarifRun(string $toolName, array $results): array
    {
        return [
            'tool' => ['driver' => ['name' => $toolName]],
            'results' => $results,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function sarifResult(string $ruleId, string $message, string $uri, int $startLine): array
    {
        return [
            'ruleId' => $ruleId,
            'message' => ['text' => $message],
            'locations' => [[
                'physicalLocation' => [
                    'artifactLocation' => ['uri' => $uri],
                    'region' => ['startLine' => $startLine],
                ],
            ]],
        ];
    }

    /**
     * @param list<mixed> $runs
     */
    private function writeSarif(array $runs, string $filename = 'report.sarif'): string
    {
        $path = $this->tmpDir.'/'.$filename;
        $this->filesystem->dumpFile($path, json_encode(['version' => '2.1.0', 'runs' => $runs], \JSON_THROW_ON_ERROR));

        return $path;
    }
}
