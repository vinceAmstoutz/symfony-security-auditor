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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScopedScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SkippedFileReason;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan\Fixture\FixedScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan\Fixture\RecordingReportingScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan\Fixture\RecordingScopedScanner;

final class ScopedScanTest extends TestCase
{
    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidProjectFileException
     */
    #[DataProvider('pathsThatNameNothing')]
    public function test_without_a_path_the_configured_scan_is_used_and_maps_itself(array $scanPaths): void
    {
        $configured = [$this->file('src/A.php')];
        $recordingScopedScanner = new RecordingScopedScanner($configured, [$this->file('apps/api/B.php')]);

        $scopedScanResult = ScopedScan::resolve($recordingScopedScanner, '/project', $scanPaths);

        self::assertSame($configured, $scopedScanResult->audited->files);
        self::assertSame($configured, $scopedScanResult->mappingFiles);
        self::assertSame([['scan', null]], $recordingScopedScanner->calls);
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function pathsThatNameNothing(): iterable
    {
        yield 'no path' => [[]];
        yield 'blank paths' => [['', '   ']];
        yield 'the project root, however it is spelled' => [['.', './', '/']];
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidProjectFileException
     */
    #[DataProvider('pathsThatReachTheConfiguredFiles')]
    public function test_a_path_the_configured_scan_reaches_audits_the_configured_files_under_it_and_nothing_else(array $scanPaths): void
    {
        $projectFile = $this->file('src/Controller/A.php');
        $configured = [$projectFile, $this->file('src/Service/B.php'), $this->file('config/services.yaml')];
        $recordingScopedScanner = new RecordingScopedScanner($configured, [$this->file('src/Controller/A.php'), $this->file('src/Controller/Unconfigured.php')]);

        $scopedScanResult = ScopedScan::resolve($recordingScopedScanner, '/project', $scanPaths);

        self::assertSame([$projectFile], $scopedScanResult->audited->files);
        self::assertSame($configured, $scopedScanResult->mappingFiles);
        self::assertSame([['scan', null]], $recordingScopedScanner->calls);
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function pathsThatReachTheConfiguredFiles(): iterable
    {
        yield 'a directory' => [['src/Controller']];
        yield 'a directory spelled with a leading dot, a trailing slash and backslashes' => [['./src\\Controller/']];
        yield 'a directory spelled with blanks around it' => [['  src/Controller  ']];
        yield 'a directory spelled with a parent segment' => [['src/Service/../Controller']];
        yield 'a single file' => [['src/Controller/A.php']];
        yield 'a directory and a path the configuration does not reach' => [['apps/api', 'src/Controller']];
        yield 'the same directory twice' => [['src/Controller', 'src/Controller']];
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_several_paths_audit_the_configured_files_under_any_of_them_in_scan_order(): void
    {
        $projectFile = $this->file('src/Service/B.php');
        $controller = $this->file('src/Controller/A.php');
        $recordingScopedScanner = new RecordingScopedScanner([$controller, $projectFile, $this->file('config/services.yaml')], []);

        $scopedScanResult = ScopedScan::resolve($recordingScopedScanner, '/project', ['src/Service', 'src/Controller']);

        self::assertSame([$controller, $projectFile], $scopedScanResult->audited->files);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_path_that_only_starts_like_a_configured_directory_does_not_reach_it(): void
    {
        $projectFile = $this->file('apps/api-shared/C.php');
        $outside = $this->file('apps/api/B.php');
        $recordingScopedScanner = new RecordingScopedScanner([$projectFile], [$outside]);

        $scopedScanResult = ScopedScan::resolve($recordingScopedScanner, '/project', ['apps/api']);

        self::assertSame([$outside], $scopedScanResult->audited->files);
        self::assertSame([['scan', null], ['scanWithin', ['apps/api']]], $recordingScopedScanner->calls);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_paths_the_configured_scan_does_not_reach_are_scanned_themselves_and_the_configured_files_stay_in_the_mapping(): void
    {
        $projectFile = $this->file('config/packages/security.yaml');
        $outside = $this->file('apps/api/B.php');
        $recordingScopedScanner = new RecordingScopedScanner([$projectFile], [$outside]);

        $scopedScanResult = ScopedScan::resolve($recordingScopedScanner, '/project', ['./apps/api/', ' apps\\web ', '', 'apps/api']);

        self::assertSame([$outside], $scopedScanResult->audited->files);
        self::assertSame([$projectFile, $outside], $scopedScanResult->mappingFiles);
        self::assertSame([['scan', null], ['scanWithin', ['apps/api', 'apps/web', 'apps/api']]], $recordingScopedScanner->calls);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_paths_the_configured_scan_does_not_reach_audit_nothing_for_a_scanner_that_cannot_take_them(): void
    {
        $projectFile = $this->file('src/A.php');
        $fixedScanner = new FixedScanner([$projectFile]);

        $scopedScanResult = ScopedScan::resolve($fixedScanner, '/project', ['apps/api']);

        self::assertSame([], $scopedScanResult->audited->files);
        self::assertSame([], $scopedScanResult->audited->skippedFiles);
        self::assertSame([$projectFile], $scopedScanResult->mappingFiles);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_path_the_configured_scan_reaches_keeps_the_files_the_scanner_left_out(): void
    {
        $skippedFile = new SkippedFile('src/Big.php', SkippedFileReason::TooLarge);
        $configured = [$this->file('src/A.php'), $this->file('config/services.yaml')];
        $recordingReportingScanner = new RecordingReportingScanner(new ProjectFileScan($configured, [$skippedFile]), new ProjectFileScan([$this->file('apps/api/B.php')], []));

        $scopedScanResult = ScopedScan::resolve($recordingReportingScanner, '/project', ['src']);

        self::assertSame([$configured[0]], $scopedScanResult->audited->files);
        self::assertSame([$skippedFile], $scopedScanResult->audited->skippedFiles);
        self::assertSame($configured, $scopedScanResult->mappingFiles);
        self::assertSame([[]], $recordingReportingScanner->requestedPaths);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_path_the_configured_scan_does_not_reach_reports_the_files_the_scanner_left_out_of_that_path(): void
    {
        $skippedFile = new SkippedFile('apps/api/Big.php', SkippedFileReason::TooLarge);
        $projectFile = $this->file('src/A.php');
        $outside = $this->file('apps/api/B.php');
        $recordingReportingScanner = new RecordingReportingScanner(
            new ProjectFileScan([$projectFile], [new SkippedFile('src/Huge.php', SkippedFileReason::Unreadable)]),
            new ProjectFileScan([$outside], [$skippedFile]),
        );

        $scopedScanResult = ScopedScan::resolve($recordingReportingScanner, '/project', ['apps/api']);

        self::assertSame([$outside], $scopedScanResult->audited->files);
        self::assertSame([$skippedFile], $scopedScanResult->audited->skippedFiles);
        self::assertSame([$projectFile, $outside], $scopedScanResult->mappingFiles);
        self::assertSame([[], ['apps/api']], $recordingReportingScanner->requestedPaths);
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function file(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/project/'.$relativePath, '<?php');
    }
}
