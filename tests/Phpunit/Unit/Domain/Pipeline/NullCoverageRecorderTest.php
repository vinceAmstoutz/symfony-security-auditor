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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Pipeline;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;

final class NullCoverageRecorderTest extends TestCase
{
    public function test_record_coverage_is_noop(): void
    {
        $nullCoverageRecorder = new NullCoverageRecorder();

        $nullCoverageRecorder->recordCoverage('attacker', 'src/A.php', 'analyzed');

        self::assertSame([], $nullCoverageRecorder->drainReviewedFindings());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    public function test_record_reviewed_finding_does_not_populate_the_drain(): void
    {
        $nullCoverageRecorder = new NullCoverageRecorder();

        $nullCoverageRecorder->recordReviewedFinding($this->makeVulnerability());

        self::assertSame([], $nullCoverageRecorder->drainReviewedFindings());
    }

    public function test_drain_reviewed_findings_always_returns_empty(): void
    {
        $nullCoverageRecorder = new NullCoverageRecorder();

        self::assertSame([], $nullCoverageRecorder->drainReviewedFindings());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    private function makeVulnerability(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test', 0.9),
            new CodeLocation('src/A.php', 1, 5),
            new VulnerabilityNarrative('Test', 'Inject SQL', "' OR 1=1--", 'Use prepared statements'),
            '$query',
        );
    }
}
