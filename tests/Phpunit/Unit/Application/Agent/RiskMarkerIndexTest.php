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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;

final class RiskMarkerIndexTest extends TestCase
{
    public function test_for_chunk_returns_all_markers_of_files_in_the_chunk(): void
    {
        $riskMarkerIndex = new RiskMarkerIndex([
            RiskMarker::create('src/A.php', 1, 'p1', 'd1'),
            RiskMarker::create('src/A.php', 2, 'p2', 'd2'),
            RiskMarker::create('src/B.php', 3, 'p3', 'd3'),
        ]);

        $markers = $riskMarkerIndex->forChunk([$this->file('src/A.php')]);

        self::assertCount(2, $markers);
        self::assertSame([1, 2], [$markers[0]->line(), $markers[1]->line()]);
    }

    public function test_for_chunk_excludes_markers_of_files_not_in_the_chunk(): void
    {
        $riskMarkerIndex = new RiskMarkerIndex([
            RiskMarker::create('src/A.php', 1, 'p1', 'd1'),
            RiskMarker::create('src/B.php', 3, 'p3', 'd3'),
        ]);

        $markers = $riskMarkerIndex->forChunk([$this->file('src/A.php')]);

        self::assertCount(1, $markers);
        self::assertSame('src/A.php', $markers[0]->filePath());
    }

    public function test_for_chunk_is_empty_when_no_file_has_markers(): void
    {
        $riskMarkerIndex = new RiskMarkerIndex([RiskMarker::create('src/A.php', 1, 'p', 'd')]);

        self::assertSame([], $riskMarkerIndex->forChunk([$this->file('src/Other.php')]));
    }

    public function test_files_with_markers_keeps_only_flagged_files_in_order(): void
    {
        $riskMarkerIndex = new RiskMarkerIndex([RiskMarker::create('src/B.php', 1, 'p', 'd')]);

        $kept = $riskMarkerIndex->filesWithMarkers([
            $this->file('src/A.php'),
            $this->file('src/B.php'),
            $this->file('src/C.php'),
        ]);

        self::assertCount(1, $kept);
        self::assertSame('src/B.php', $kept[0]->relativePath());
    }

    private function file(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }
}
