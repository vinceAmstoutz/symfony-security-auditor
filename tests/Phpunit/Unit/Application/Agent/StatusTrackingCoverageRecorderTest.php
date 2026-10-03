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
