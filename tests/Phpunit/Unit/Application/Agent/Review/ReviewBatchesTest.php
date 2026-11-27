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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewBatches;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewBatchSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\NullCoverageRecorder;

final class ReviewBatchesTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_grouped_batches_hold_one_file_each_and_keep_each_finding_input_index(): void
    {
        [$a1, $b1, $a2, $a3] = [$this->findingAt('src/A.php', 1), $this->findingAt('src/B.php', 1), $this->findingAt('src/A.php', 2), $this->findingAt('src/A.php', 3)];

        [$batches, $indexes] = ReviewBatches::of([$a1, $b1, $a2, $a3], [1, 3, 4, 6], new ReviewBatchSettings(2, false, false, new NullCoverageRecorder(), null, true));

        self::assertSame([[$a1, $a2], [$a3], [$b1]], $batches);
        self::assertSame([1, 4, 6, 3], $indexes);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_ungrouped_batches_follow_the_input_order(): void
    {
        [$a1, $b1, $a2] = [$this->findingAt('src/A.php', 1), $this->findingAt('src/B.php', 1), $this->findingAt('src/A.php', 2)];

        self::assertSame(
            [[[$a1, $b1], [$a2]], [1, 3, 4]],
            ReviewBatches::of([$a1, $b1, $a2], [1, 3, 4], new ReviewBatchSettings(2, false, false, new NullCoverageRecorder(), null)),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function findingAt(string $filePath, int $line): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Finding', 0.8),
            new CodeLocation($filePath, $line, $line),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
