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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\VerdictApplier;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class VerdictApplierTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_elevates_severity_when_the_verdict_is_accepted(): void
    {
        $verdictApplier = new VerdictApplier(new NullLogger());

        $vulnerability = $verdictApplier->apply($this->vulnerability(), ['accepted' => true, 'adjusted_severity' => 'critical']);

        self::assertSame(VulnerabilitySeverity::CRITICAL, $vulnerability->severity());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_does_not_adjust_severity_when_the_verdict_is_rejected(): void
    {
        $verdictApplier = new VerdictApplier(new NullLogger());

        $vulnerability = $verdictApplier->apply($this->vulnerability(), ['accepted' => false, 'adjusted_severity' => 'critical']);

        self::assertSame(VulnerabilitySeverity::HIGH, $vulnerability->severity());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('stringifiedFalseCases')]
    public function test_it_treats_a_stringified_false_as_rejected_regardless_of_case_or_surrounding_whitespace(string $accepted): void
    {
        $verdictApplier = new VerdictApplier(new NullLogger());

        $vulnerability = $verdictApplier->apply($this->vulnerability(), ['accepted' => $accepted]);

        self::assertFalse($vulnerability->isReviewerValidated());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function stringifiedFalseCases(): iterable
    {
        yield 'lowercase' => ['false'];
        yield 'uppercase' => ['FALSE'];
        yield 'padded' => [' false '];
        yield 'padded uppercase' => ['  FALSE  '];
    }

    /**
     * @param array<string, mixed>|list<array<string, mixed>> $review
     */
    #[DataProvider('payloadsThatHoldAVerdict')]
    public function test_it_tells_a_payload_that_holds_a_verdict(array $review): void
    {
        self::assertTrue((new VerdictApplier(new NullLogger()))->hasVerdict($review));
    }

    /**
     * @return iterable<string, array{array<string, mixed>|list<array<string, mixed>>}>
     */
    public static function payloadsThatHoldAVerdict(): iterable
    {
        yield 'an acceptance' => [['accepted' => true]];
        yield 'an explicit rejection' => [['accepted' => false]];
        yield 'a stringified rejection' => [['accepted' => 'false']];
        yield 'a verdict wrapped in a one-element list' => [[['accepted' => false]]];
    }

    /**
     * @param array<string, mixed>|list<array<string, mixed>> $review
     */
    #[DataProvider('payloadsThatHoldNoVerdict')]
    public function test_it_tells_a_payload_that_holds_no_verdict(array $review): void
    {
        self::assertFalse((new VerdictApplier(new NullLogger()))->hasVerdict($review));
    }

    /**
     * @return iterable<string, array{array<string, mixed>|list<array<string, mixed>>}>
     */
    public static function payloadsThatHoldNoVerdict(): iterable
    {
        yield 'an empty payload' => [[]];
        yield 'notes only' => [['reviewer_notes' => 'not exploitable']];
        yield 'an accepted flag set to null' => [['accepted' => null]];
        yield 'notes only wrapped in a one-element list' => [[['reviewer_notes' => 'not exploitable']]];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_applying_a_payload_with_no_accepted_flag_leaves_the_finding_not_validated(): void
    {
        $vulnerability = (new VerdictApplier(new NullLogger()))->apply($this->vulnerability(), ['adjusted_severity' => 'critical']);

        self::assertFalse($vulnerability->isReviewerValidated());
        self::assertSame(VulnerabilitySeverity::HIGH, $vulnerability->severity());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
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
