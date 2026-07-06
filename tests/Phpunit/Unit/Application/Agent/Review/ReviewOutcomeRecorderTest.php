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
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewOutcomeRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullReviewerCache;

final class ReviewOutcomeRecorderTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_an_accepted_verdict_reports_the_finding_as_reviewed(): void
    {
        $progressReporter = $this->expectingReviewedEvent(true);

        $vulnerability = $this->recorder($progressReporter)->recordVerdict($this->vulnerability(), ['accepted' => true], new NullCoverageRecorder());

        self::assertTrue($vulnerability->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_a_rejected_verdict_reports_the_finding_as_reviewed(): void
    {
        $progressReporter = $this->expectingReviewedEvent(false);

        $vulnerability = $this->recorder($progressReporter)->recordVerdict($this->vulnerability(), ['accepted' => false], new NullCoverageRecorder());

        self::assertFalse($vulnerability->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_a_finding_without_any_verdict_still_reports_as_reviewed(): void
    {
        $progressReporter = $this->expectingReviewedEvent(false);

        $vulnerability = $this->recorder($progressReporter)->recordVerdict($this->vulnerability(), null, new NullCoverageRecorder());

        self::assertFalse($vulnerability->isReviewerValidated());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_an_errored_review_still_reports_the_finding_as_reviewed(): void
    {
        $progressReporter = $this->expectingReviewedEvent(false);

        $vulnerability = $this->recorder($progressReporter)->recordReviewError($this->vulnerability(), new RuntimeException('llm down'), new NullCoverageRecorder());

        self::assertFalse($vulnerability->isReviewerValidated());
    }

    private function expectingReviewedEvent(bool $accepted): ProgressReporterInterface
    {
        $progressReporter = $this->createMock(ProgressReporterInterface::class);
        $progressReporter->expects(self::once())->method('report')->with(
            'review.finding.reviewed',
            ['accepted' => $accepted, 'type' => 'sql_injection', 'file' => 'src/A.php', 'line' => 18],
        );

        return $progressReporter;
    }

    private function recorder(ProgressReporterInterface $progressReporter): ReviewOutcomeRecorder
    {
        return new ReviewOutcomeRecorder(
            new VerdictApplier(new NullLogger()),
            new ReviewerVerdictCache(new NullReviewerCache(), new NullLogger()),
            new NullLogger(),
            $progressReporter,
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    private function vulnerability(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'T', 0.9),
            new CodeLocation('src/A.php', 18, 20),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
