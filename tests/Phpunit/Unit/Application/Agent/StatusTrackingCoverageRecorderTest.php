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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\StatusTrackingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class StatusTrackingCoverageRecorderTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_forwards_every_call_to_the_recorder_it_wraps(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder($recordingCoverageRecorder);
        $vulnerability = $this->makeVulnerability('reviewed');
        $found = $this->makeVulnerability('found');

        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $statusTrackingCoverageRecorder->recordReviewedFinding($vulnerability);
        $statusTrackingCoverageRecorder->recordFoundVulnerability($found);

        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'analyzed']], $recordingCoverageRecorder->coverage);
        self::assertSame([$vulnerability], $statusTrackingCoverageRecorder->drainReviewedFindings());
        self::assertSame([$found], $statusTrackingCoverageRecorder->drainFoundVulnerabilities());
        self::assertSame([], $recordingCoverageRecorder->found);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_says_why_a_chunk_ended_errored(): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new RecordingCoverageRecorder());
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'errored');
        $statusTrackingCoverageRecorder->recordFailureReason('attacker', 'src/A.php', 'tool-call limit reached');

        self::assertSame('tool-call limit reached', $statusTrackingCoverageRecorder->chunkFailureReason([ProjectFile::create('src/B.php', 'src/B.php', '<?php'), ProjectFile::create('src/A.php', 'src/A.php', '<?php')]));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_chunk_with_no_recorded_reason_has_none(): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new RecordingCoverageRecorder());
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'errored');

        self::assertNull($statusTrackingCoverageRecorder->chunkFailureReason([ProjectFile::create('src/A.php', 'src/A.php', '<?php')]));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_file_analyzed_after_it_failed_no_longer_has_a_failure_reason(): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new RecordingCoverageRecorder());
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'errored');
        $statusTrackingCoverageRecorder->recordFailureReason('attacker', 'src/A.php', 'tool-call limit reached');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'analyzed');

        self::assertNull($statusTrackingCoverageRecorder->chunkFailureReason([ProjectFile::create('src/A.php', 'src/A.php', '<?php')]));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_reason_for_another_stage_is_not_a_reason_the_attacker_chunk_failed(): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new RecordingCoverageRecorder());
        $statusTrackingCoverageRecorder->recordFailureReason('reviewer', 'src/A.php', 'review call failed');

        self::assertNull($statusTrackingCoverageRecorder->chunkFailureReason([ProjectFile::create('src/A.php', 'src/A.php', '<?php')]));
    }

    public function test_it_forwards_a_failure_reason_to_the_recorder_it_wraps(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        (new StatusTrackingCoverageRecorder($recordingCoverageRecorder))->recordFailureReason('attacker', 'src/A.php', 'tool-call limit reached');

        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'reason' => 'tool-call limit reached']], $recordingCoverageRecorder->failureReasons);
    }

    public function test_it_lists_the_files_the_attacker_last_left_analyzed_or_cached(): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new RecordingCoverageRecorder());

        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Analyzed.php', 'analyzed');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Errored.php', 'errored');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Cached.php', 'cached');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Retried.php', 'analyzed');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Retried.php', 'aborted');
        $statusTrackingCoverageRecorder->recordCoverage('reviewer', 'src/Reviewed.php', 'analyzed');

        self::assertSame(['src/Analyzed.php', 'src/Cached.php'], $statusTrackingCoverageRecorder->analyzedFiles());
    }

    public function test_it_lists_the_files_the_attacker_left_analyzed_on_more_than_a_partial_look(): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new RecordingCoverageRecorder());

        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Judged.php', 'analyzed');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Inconclusive.php', 'analyzed');
        $statusTrackingCoverageRecorder->recordInconclusiveAnalysis('attacker', 'src/Inconclusive.php');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Cached.php', 'cached');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Errored.php', 'errored');

        self::assertSame(['src/Judged.php', 'src/Cached.php'], $statusTrackingCoverageRecorder->conclusiveFiles());
        self::assertSame(['src/Judged.php', 'src/Inconclusive.php', 'src/Cached.php'], $statusTrackingCoverageRecorder->analyzedFiles());
    }

    public function test_a_file_judged_again_after_a_partial_look_is_conclusive(): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new RecordingCoverageRecorder());

        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $statusTrackingCoverageRecorder->recordInconclusiveAnalysis('attacker', 'src/A.php');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'analyzed');

        self::assertSame(['src/A.php'], $statusTrackingCoverageRecorder->conclusiveFiles());
    }

    public function test_a_partial_look_of_another_stage_leaves_the_attacker_files_conclusive(): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new RecordingCoverageRecorder());

        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $statusTrackingCoverageRecorder->recordInconclusiveAnalysis('reviewer', 'src/A.php');

        self::assertSame(['src/A.php'], $statusTrackingCoverageRecorder->conclusiveFiles());
    }

    public function test_it_forwards_a_partial_look_to_the_recorder_it_wraps(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        (new StatusTrackingCoverageRecorder($recordingCoverageRecorder))->recordInconclusiveAnalysis('attacker', 'src/A.php');

        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php']], $recordingCoverageRecorder->inconclusive);
    }

    public function test_it_keeps_a_partial_look_when_the_recorder_it_wraps_does_not(): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new NullCoverageRecorder());

        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'analyzed');
        $statusTrackingCoverageRecorder->recordInconclusiveAnalysis('attacker', 'src/A.php');

        self::assertSame([], $statusTrackingCoverageRecorder->conclusiveFiles());
    }

    /**
     * @param list<string> $files
     *
     * @throws InvalidProjectFileException
     */
    #[DataProvider('chunkOutcomes')]
    public function test_it_says_how_the_attacker_left_a_chunk(array $files, string $expectedStatus): void
    {
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder(new RecordingCoverageRecorder());
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Analyzed.php', 'analyzed');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Cached.php', 'cached');
        $statusTrackingCoverageRecorder->recordCoverage('attacker', 'src/Errored.php', 'errored');

        $chunk = array_map(static fn (string $file): ProjectFile => ProjectFile::create($file, $file, '<?php'), $files);

        self::assertSame($expectedStatus, $statusTrackingCoverageRecorder->chunkStatus($chunk));
    }

    /**
     * @return iterable<string, array{list<string>, string}>
     */
    public static function chunkOutcomes(): iterable
    {
        yield 'every file analyzed or served from the cache' => [['src/Analyzed.php', 'src/Cached.php'], 'analyzed'];
        yield 'a file whose call failed' => [['src/Analyzed.php', 'src/Errored.php'], 'errored'];
        yield 'a file the attacker never reached' => [['src/Analyzed.php', 'src/Unreached.php'], 'errored'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerability(string $title): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, $title, 0.9),
            new CodeLocation('src/A.php', 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
