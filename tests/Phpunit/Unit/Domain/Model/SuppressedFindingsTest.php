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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SuppressedFindings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class SuppressedFindingsTest extends TestCase
{
    public function test_a_run_that_withheld_nothing_lists_no_fingerprint(): void
    {
        self::assertSame([], (new SuppressedFindings())->fingerprints());
    }

    public function test_the_baseline_credits_spent_before_the_review_come_before_the_findings_removed_afterwards(): void
    {
        $suppressedFindings = new SuppressedFindings(['SSA-BEFORE-1', 'SSA-BEFORE-2'], ['SSA-AFTER']);

        self::assertSame(['SSA-BEFORE-1', 'SSA-BEFORE-2', 'SSA-AFTER'], $suppressedFindings->fingerprints());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_removed_findings_are_appended_after_the_ones_already_removed_and_the_original_is_left_alone(): void
    {
        $suppressedFindings = new SuppressedFindings(['SSA-BEFORE'], ['SSA-FIRST']);
        $vulnerability = $this->vulnerability('second');
        $third = $this->vulnerability('third');

        $withRemoved = $suppressedFindings->withRemoved([$vulnerability, $third]);

        self::assertSame(['SSA-BEFORE', 'SSA-FIRST', $vulnerability->fingerprint(), $third->fingerprint()], $withRemoved->fingerprints());
        self::assertSame(['SSA-BEFORE'], $withRemoved->acceptedBeforeReview);
        self::assertSame(['SSA-BEFORE', 'SSA-FIRST'], $suppressedFindings->fingerprints());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerability(string $discriminator): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Test '.$discriminator, 0.9),
            new CodeLocation('src/'.$discriminator.'.php', 1, 5),
            new VulnerabilityNarrative('Test vulnerability', 'Inject', "' OR 1=1", 'Fix it'),
            '$query',
        );
    }
}
