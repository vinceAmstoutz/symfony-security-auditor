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
        $kept = $this->file('apps/api/B.php');
        $fixedScanner = new FixedScanner([$this->file('src/A.php'), $kept, $this->file('apps/api-shared/C.php')]);

        self::assertSame([$kept], ScopedScan::files($fixedScanner, '/project', ['apps/api']));
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function file(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/project/'.$relativePath, '<?php');
    }
}
