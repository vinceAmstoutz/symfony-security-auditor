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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\FindingPrecedence;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class FindingPrecedenceTest extends TestCase
{
    /**
     * @param array{VulnerabilitySeverity, float, bool} $challenger severity, confidence, validated
     * @param array{VulnerabilitySeverity, float, bool} $incumbent  severity, confidence, validated
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('precedenceCases')]
    public function test_it_tells_which_finding_a_collapse_keeps(array $challenger, array $incumbent, bool $expected): void
    {
        self::assertSame($expected, FindingPrecedence::prevails($this->finding(...$challenger), $this->finding(...$incumbent)));
    }

    /**
     * @return iterable<string, array{array{VulnerabilitySeverity, float, bool}, array{VulnerabilitySeverity, float, bool}, bool}>
     */
    public static function precedenceCases(): iterable
    {
        yield 'higher severity prevails' => [[VulnerabilitySeverity::CRITICAL, 0.6, false], [VulnerabilitySeverity::HIGH, 0.9, false], true];
        yield 'lower severity does not prevail' => [[VulnerabilitySeverity::HIGH, 0.9, false], [VulnerabilitySeverity::CRITICAL, 0.6, false], false];
        yield 'next severity down does not prevail' => [[VulnerabilitySeverity::INFO, 0.9, false], [VulnerabilitySeverity::LOW, 0.6, false], false];
        yield 'same severity, higher confidence prevails' => [[VulnerabilitySeverity::HIGH, 0.91, false], [VulnerabilitySeverity::HIGH, 0.9, false], true];
        yield 'same severity, lower confidence does not prevail' => [[VulnerabilitySeverity::HIGH, 0.9, false], [VulnerabilitySeverity::HIGH, 0.91, false], false];
        yield 'same severity and confidence keeps the incumbent' => [[VulnerabilitySeverity::HIGH, 0.9, false], [VulnerabilitySeverity::HIGH, 0.9, false], false];
        yield 'same severity and confidence, both validated, keeps the incumbent' => [[VulnerabilitySeverity::HIGH, 0.9, true], [VulnerabilitySeverity::HIGH, 0.9, true], false];
        yield 'severity outweighs confidence' => [[VulnerabilitySeverity::CRITICAL, 0.1, false], [VulnerabilitySeverity::HIGH, 1.0, false], true];
        yield 'validated prevails over unvalidated of a higher severity' => [[VulnerabilitySeverity::LOW, 0.1, true], [VulnerabilitySeverity::CRITICAL, 1.0, false], true];
        yield 'unvalidated does not prevail over validated of a lower severity' => [[VulnerabilitySeverity::CRITICAL, 1.0, false], [VulnerabilitySeverity::LOW, 0.1, true], false];
        yield 'higher severity prevails among validated' => [[VulnerabilitySeverity::HIGH, 0.6, true], [VulnerabilitySeverity::MEDIUM, 0.9, true], true];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_collapses_findings_sharing_an_id_in_the_order_each_id_first_appeared(): void
    {
        $vulnerability = $this->finding(VulnerabilitySeverity::HIGH, 0.9, false);
        $otherId = $this->finding(VulnerabilitySeverity::LOW, 0.9, false, 20);
        $firstIdRaised = $this->finding(VulnerabilitySeverity::CRITICAL, 0.9, false);
        $firstIdLowered = $this->finding(VulnerabilitySeverity::MEDIUM, 0.9, false);

        self::assertSame(
            [$firstIdRaised, $otherId],
            FindingPrecedence::collapseById([$vulnerability, $otherId, $firstIdRaised, $firstIdLowered]),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_keeps_the_first_of_two_findings_of_equal_rank(): void
    {
        $vulnerability = $this->finding(VulnerabilitySeverity::HIGH, 0.9, false);
        $second = $this->finding(VulnerabilitySeverity::HIGH, 0.9, false);

        self::assertSame([$vulnerability], FindingPrecedence::collapseById([$vulnerability, $second]));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function finding(VulnerabilitySeverity $vulnerabilitySeverity, float $confidence, bool $validated, int $lineStart = 10): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, $vulnerabilitySeverity, 'title', $confidence),
            new CodeLocation('src/A.php', $lineStart, $lineStart + 5),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        )->withReviewerValidation($validated);
    }
}
