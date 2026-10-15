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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SuppressedFinding;
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
        $suppressedFindings = new SuppressedFindings();

        self::assertSame([], $suppressedFindings->fingerprints());
        self::assertSame([], $suppressedFindings->baselineFingerprints());
        self::assertSame([], $suppressedFindings->baselineFingerprintsAcceptedBeforeReview());
    }

    public function test_the_findings_accepted_before_the_review_come_before_the_ones_removed_afterwards(): void
    {
        $suppressedFindings = new SuppressedFindings(
            [new SuppressedFinding('SSA-BEFORE-1', 'SSA-CREDIT-1'), new SuppressedFinding('SSA-BEFORE-2', 'SSA-CREDIT-2')],
            [new SuppressedFinding('SSA-AFTER', 'SSA-CREDIT-3')],
        );

        self::assertSame(['SSA-BEFORE-1', 'SSA-BEFORE-2', 'SSA-AFTER'], $suppressedFindings->fingerprints());
        self::assertSame(['SSA-CREDIT-1', 'SSA-CREDIT-2', 'SSA-CREDIT-3'], $suppressedFindings->baselineFingerprints());
        self::assertSame(['SSA-CREDIT-1', 'SSA-CREDIT-2'], $suppressedFindings->baselineFingerprintsAcceptedBeforeReview());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_removed_findings_are_appended_after_the_ones_already_removed_and_the_original_is_left_alone(): void
    {
        $suppressedFindings = new SuppressedFindings([new SuppressedFinding('SSA-BEFORE', 'SSA-BEFORE')], [new SuppressedFinding('SSA-FIRST', 'SSA-FIRST')]);
        $vulnerability = $this->vulnerability('second');
        $third = $this->vulnerability('third');

        $withRemoved = $suppressedFindings->withRemoved([3 => $vulnerability, 7 => $third]);

        self::assertSame(['SSA-BEFORE', 'SSA-FIRST', $vulnerability->fingerprint(), $third->fingerprint()], $withRemoved->fingerprints());
        self::assertSame(['SSA-BEFORE', 'SSA-FIRST', $vulnerability->fingerprint(), $third->fingerprint()], $withRemoved->baselineFingerprints());
        self::assertSame(['SSA-BEFORE'], $withRemoved->baselineFingerprintsAcceptedBeforeReview());
        self::assertSame(['SSA-BEFORE', 'SSA-FIRST'], $suppressedFindings->fingerprints());
    }

    public function test_a_finding_removed_through_another_baseline_fingerprint_is_listed_under_its_own(): void
    {
        $suppressedFindings = (new SuppressedFindings())->withRemovedFindings([new SuppressedFinding('SSA-OWN', 'SSA-FORMER')]);

        self::assertSame(['SSA-OWN'], $suppressedFindings->fingerprints());
        self::assertSame(['SSA-FORMER'], $suppressedFindings->baselineFingerprints());
        self::assertSame([], $suppressedFindings->baselineFingerprintsAcceptedBeforeReview());
    }

    public function test_naming_a_finding_after_its_entry_keeps_the_baseline_fingerprint_it_spent(): void
    {
        $suppressedFindings = new SuppressedFindings([new SuppressedFinding('SSA-ATTACKER', 'SSA-ATTACKER')]);

        $named = $suppressedFindings->withAcceptedBeforeReviewNamedBy(['SSA-ATTACKER' => ['SSA-CORRECTED']]);

        self::assertSame(['SSA-CORRECTED'], $named->fingerprints());
        self::assertSame(['SSA-ATTACKER'], $named->baselineFingerprintsAcceptedBeforeReview());
        self::assertSame(['SSA-ATTACKER'], $suppressedFindings->fingerprints());
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
