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
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan\Fixture\FixedScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Scan\Fixture\RecordingScopedScanner;

final class ScopedScanTest extends TestCase
{
    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidProjectFileException
     */
    #[DataProvider('pathsThatNameNothing')]
    public function test_without_a_path_the_configured_scan_is_used(array $scanPaths): void
    {
        $configured = [$this->file('src/A.php')];
        $recordingScopedScanner = new RecordingScopedScanner($configured, [$this->file('apps/api/B.php')]);

        self::assertSame($configured, ScopedScan::files($recordingScopedScanner, '/project', $scanPaths));
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
     * @throws InvalidProjectFileException
     */
    public function test_given_paths_replace_the_configured_scan_when_the_scanner_can_take_them(): void
    {
        $scoped = [$this->file('apps/api/B.php')];
        $recordingScopedScanner = new RecordingScopedScanner([$this->file('src/A.php')], $scoped);

        self::assertSame($scoped, ScopedScan::files($recordingScopedScanner, '/project', ['./apps/api/', ' apps\\web ', '', 'apps/api']));
        self::assertSame([['scanWithin', ['apps/api', 'apps/web', 'apps/api']]], $recordingScopedScanner->calls);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_scanner_that_cannot_take_paths_has_its_result_narrowed_to_them(): void
    {
        $projectFile = $this->file('apps/api/B.php');
        $fixedScanner = new FixedScanner([$this->file('src/A.php'), $projectFile, $this->file('apps/api-shared/C.php')]);

        self::assertSame([$projectFile], ScopedScan::files($fixedScanner, '/project', ['apps/api']));
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidProjectFileException
     */
    #[DataProvider('pathsThatNameNothing')]
    public function test_without_a_path_the_mapping_is_built_from_the_configured_scan_without_scanning_again(array $scanPaths): void
    {
        $configured = [$this->file('src/A.php')];
        $recordingScopedScanner = new RecordingScopedScanner($configured, [$this->file('apps/api/B.php')]);
        $scopedFiles = ScopedScan::files($recordingScopedScanner, '/project', $scanPaths);

        self::assertSame($configured, ScopedScan::mappingFiles($recordingScopedScanner, '/project', $scanPaths, $scopedFiles));
        self::assertSame([['scan', null]], $recordingScopedScanner->calls);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_path_leaves_the_configured_scope_in_the_mapping_and_adds_what_only_the_path_reaches(): void
    {
        $projectFile = $this->file('config/packages/security.yaml');
        $controller = $this->file('src/Controller/A.php');
        $outside = $this->file('apps/api/src/B.php');
        $recordingScopedScanner = new RecordingScopedScanner([$projectFile, $controller], [$outside]);

        self::assertSame(
            [$projectFile, $controller, $outside],
            ScopedScan::mappingFiles($recordingScopedScanner, '/project', ['apps/api'], [$outside]),
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_file_the_configured_scope_and_the_path_both_reach_is_mapped_once_as_the_configured_scan_read_it(): void
    {
        $projectFile = $this->file('src/Controller/A.php');
        $scopedController = $this->file('src/Controller/A.php');
        $recordingScopedScanner = new RecordingScopedScanner([$projectFile], [$scopedController]);

        $mappingFiles = ScopedScan::mappingFiles($recordingScopedScanner, '/project', ['src/Controller'], [$scopedController]);

        self::assertCount(1, $mappingFiles);
        self::assertSame($projectFile, $mappingFiles[0]);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_scanner_that_cannot_take_paths_maps_everything_it_scans(): void
    {
        $projectFile = $this->file('apps/api/B.php');
        $outOfScope = $this->file('apps/web/C.php');
        $fixedScanner = new FixedScanner([$outOfScope, $projectFile]);

        self::assertSame(
            [$outOfScope, $projectFile],
            ScopedScan::mappingFiles($fixedScanner, '/project', ['apps/api'], ScopedScan::files($fixedScanner, '/project', ['apps/api'])),
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function file(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/project/'.$relativePath, '<?php');
    }
}
