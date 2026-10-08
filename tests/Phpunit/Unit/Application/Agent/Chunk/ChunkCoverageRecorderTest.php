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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class ChunkCoverageRecorderTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_an_errored_chunk_is_recorded_with_the_reason_for_each_of_its_files(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        ChunkCoverageRecorder::recordErrored([ProjectFile::create('src/A.php', 'src/A.php', '<?php'), ProjectFile::create('src/B.php', 'src/B.php', '<?php')], 'tool-call limit reached', $recordingCoverageRecorder);

        self::assertSame(
            [['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'], ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'errored']],
            $recordingCoverageRecorder->coverage,
        );
        self::assertSame(
            [['stage' => 'attacker', 'filePath' => 'src/A.php', 'reason' => 'tool-call limit reached'], ['stage' => 'attacker', 'filePath' => 'src/B.php', 'reason' => 'tool-call limit reached']],
            $recordingCoverageRecorder->failureReasons,
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_an_errored_chunk_is_still_recorded_when_the_recorder_keeps_no_reasons(): void
    {
        $coverageRecorder = $this->createMock(CoverageRecorderInterface::class);
        $coverageRecorder->expects(self::once())->method('recordCoverage')->with('attacker', 'src/A.php', 'errored');

        ChunkCoverageRecorder::recordErrored([ProjectFile::create('src/A.php', 'src/A.php', '<?php')], 'tool-call limit reached', $coverageRecorder);
    }
}
