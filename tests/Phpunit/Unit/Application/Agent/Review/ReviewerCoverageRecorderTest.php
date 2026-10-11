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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Review;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\FindingReviewRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\ReviewerAgentHarness;

final class ReviewerCoverageRecorderTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_recorder_that_ties_entries_to_findings_is_handed_the_finding_instead_of_a_bare_entry(): void
    {
        $vulnerability = ReviewerAgentHarness::vulnerabilityAt('src/A.php');
        $mockObject = $this->createMockForIntersectionOfInterfaces([CoverageRecorderInterface::class, FindingReviewRecorderInterface::class]);
        $mockObject->expects(self::once())->method('recordFindingReview')->with($vulnerability, 'errored');
        $mockObject->expects(self::never())->method('recordCoverage');

        ReviewerCoverageRecorder::record($vulnerability, 'errored', $mockObject, new NullProgressReporter());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_any_other_recorder_gets_a_reviewer_entry_for_the_findings_file(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        ReviewerCoverageRecorder::record(ReviewerAgentHarness::vulnerabilityAt('src/A.php'), 'validated', $recordingCoverageRecorder, new NullProgressReporter());

        self::assertSame([['stage' => 'reviewer', 'filePath' => 'src/A.php', 'status' => 'validated']], $recordingCoverageRecorder->coverage);
    }
}
