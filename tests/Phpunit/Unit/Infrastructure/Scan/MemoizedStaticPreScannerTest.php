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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\MemoizedStaticPreScanner;

final class MemoizedStaticPreScannerTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_a_file_scanned_once_is_not_scanned_again(): void
    {
        $files = [$this->file('src/A.php'), $this->file('src/B.php')];
        $markers = [RiskMarker::create('src/A.php', 2, 'raw_sql', 'Raw SQL'), RiskMarker::create('src/B.php', 3, 'unserialize', 'Unserialize')];
        $staticPreScanner = $this->createMock(StaticPreScannerInterface::class);
        $staticPreScanner->expects(self::once())->method('scan')->with($files)->willReturn($markers);
        $memoizedStaticPreScanner = new MemoizedStaticPreScanner($staticPreScanner);

        $memoizedStaticPreScanner->scan($files);

        self::assertEquals($markers, $memoizedStaticPreScanner->scan($files));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidRiskMarkerException
     */
    public function test_only_the_files_not_scanned_yet_are_scanned_and_markers_follow_the_order_of_the_files(): void
    {
        $first = $this->file('src/A.php');
        $second = $this->file('src/B.php');
        $firstMarker = RiskMarker::create('src/A.php', 2, 'raw_sql', 'Raw SQL');
        $secondMarkers = [RiskMarker::create('src/B.php', 3, 'unserialize', 'Unserialize'), RiskMarker::create('src/B.php', 2, 'raw_sql', 'Raw SQL')];
        $staticPreScanner = $this->createMock(StaticPreScannerInterface::class);
        $staticPreScanner->expects(self::exactly(2))->method('scan')->willReturnCallback(
            static fn (array $files): array => [$first] === $files ? [$firstMarker] : ([$second] === $files ? $secondMarkers : []),
        );
        $memoizedStaticPreScanner = new MemoizedStaticPreScanner($staticPreScanner);

        $memoizedStaticPreScanner->scan([$first]);

        self::assertEquals([...$secondMarkers, $firstMarker], $memoizedStaticPreScanner->scan([$second, $first]));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_file_without_markers_is_not_scanned_again(): void
    {
        $files = [$this->file('src/A.php')];
        $staticPreScanner = $this->createMock(StaticPreScannerInterface::class);
        $staticPreScanner->expects(self::once())->method('scan')->willReturn([]);
        $memoizedStaticPreScanner = new MemoizedStaticPreScanner($staticPreScanner);

        $memoizedStaticPreScanner->scan($files);

        self::assertSame([], $memoizedStaticPreScanner->scan($files));
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function file(string $relativePath): ProjectFile
    {
        return ProjectFile::create($relativePath, '/app/'.$relativePath, "<?php\n\$q = 1;\n\$r = 2;\n");
    }
}
