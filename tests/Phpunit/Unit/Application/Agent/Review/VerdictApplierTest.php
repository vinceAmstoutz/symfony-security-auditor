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
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('acceptedFlagsReadAsAcceptance')]
    public function test_it_validates_the_finding_for_every_spelling_of_acceptance(mixed $accepted): void
    {
        $vulnerability = (new VerdictApplier(new NullLogger()))->apply($this->vulnerability(), ['accepted' => $accepted]);

        self::assertTrue($vulnerability->isReviewerValidated());
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function acceptedFlagsReadAsAcceptance(): iterable
    {
        yield 'boolean true' => [true];
        yield 'integer one' => [1];
        yield 'stringified true' => ['true'];
        yield 'capitalised yes' => ['Yes'];
        yield 'padded y' => [' y '];
        yield 'stringified one' => ['1'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('acceptedFlagsReadAsRejection')]
    public function test_it_rejects_the_finding_for_every_spelling_of_rejection(mixed $accepted): void
    {
        $verdictApplier = new VerdictApplier(new NullLogger());

        $vulnerability = $verdictApplier->apply($this->vulnerability(), ['accepted' => $accepted]);

        self::assertFalse($vulnerability->isReviewerValidated());
        self::assertTrue($verdictApplier->hasVerdict(['accepted' => $accepted]));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function acceptedFlagsReadAsRejection(): iterable
    {
        yield 'boolean false' => [false];
        yield 'integer zero' => [0];
        yield 'stringified false' => ['false'];
        yield 'capitalised no' => ['No'];
        yield 'padded n' => [' n '];
        yield 'stringified zero' => ['0'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('acceptedFlagsThatAreNoVerdict')]
    public function test_it_never_reads_an_accepted_flag_it_does_not_recognise_as_an_acceptance(mixed $accepted): void
    {
        $verdictApplier = new VerdictApplier(new NullLogger());

        $vulnerability = $verdictApplier->apply($this->vulnerability(), ['accepted' => $accepted, 'adjusted_severity' => 'critical']);

        self::assertFalse($verdictApplier->hasVerdict(['accepted' => $accepted]));
        self::assertFalse($vulnerability->isReviewerValidated());
        self::assertSame(VulnerabilitySeverity::HIGH, $vulnerability->severity());
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function acceptedFlagsThatAreNoVerdict(): iterable
    {
        yield 'rejected' => ['rejected'];
        yield 'reject' => ['reject'];
        yield 'accepted' => ['accepted'];
        yield 'maybe' => ['maybe'];
        yield 'an empty string' => [''];
        yield 'a blank string' => ['  '];
        yield 'an integer other than zero and one' => [2];
        yield 'a negative integer' => [-1];
        yield 'a float' => [1.0];
        yield 'a stringified float' => ['1.0'];
        yield 'a zero-padded one' => ['01'];
        yield 'a zero-padded zero' => ['00'];
        yield 'a list' => [[true]];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('adjustedSeveritiesInAnotherSpelling')]
    public function test_it_reads_an_adjusted_severity_regardless_of_case_or_surrounding_whitespace(string $adjusted): void
    {
        $vulnerability = (new VerdictApplier(new NullLogger()))->apply($this->vulnerability(), ['accepted' => true, 'adjusted_severity' => $adjusted]);

        self::assertSame(VulnerabilitySeverity::LOW, $vulnerability->severity());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function adjustedSeveritiesInAnotherSpelling(): iterable
    {
        yield 'capitalised' => ['Low'];
        yield 'uppercase' => ['LOW'];
        yield 'padded' => [' low '];
        yield 'padded and capitalised' => ["\tLow\n"];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('correctedTypesInAnotherSpelling')]
    public function test_it_reads_a_corrected_type_regardless_of_case_or_surrounding_whitespace(string $corrected): void
    {
        $vulnerability = (new VerdictApplier(new NullLogger()))->apply($this->vulnerability(), ['accepted' => true, 'corrected_type' => $corrected]);

        self::assertSame(VulnerabilityType::XSS, $vulnerability->type());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function correctedTypesInAnotherSpelling(): iterable
    {
        yield 'uppercase' => ['XSS'];
        yield 'capitalised' => ['Xss'];
        yield 'padded' => [' xss '];
        yield 'padded and uppercase' => ["\tXSS\n"];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_keeps_the_original_severity_and_type_when_the_reviewer_names_none_that_exists(): void
    {
        $vulnerability = (new VerdictApplier(new NullLogger()))->apply($this->vulnerability(), ['accepted' => true, 'adjusted_severity' => 'severe', 'corrected_type' => 'made_up']);

        self::assertSame(VulnerabilitySeverity::HIGH, $vulnerability->severity());
        self::assertSame(VulnerabilityType::SQL_INJECTION, $vulnerability->type());
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
        yield 'a spelled-out rejection' => [['accepted' => 'no']];
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
        yield 'an accepted flag the auditor cannot read' => [['accepted' => 'rejected']];
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
