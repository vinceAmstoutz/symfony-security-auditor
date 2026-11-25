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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\FindingOverlap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class FindingOverlapTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('touchingRanges')]
    public function test_a_range_sharing_only_its_first_or_last_line_overlaps(int $otherStart, int $otherEnd): void
    {
        $finding = $this->findingAt('src/A.php', VulnerabilityType::SQL_INJECTION, 10, 12);

        self::assertSame([], FindingOverlap::outside([$finding], [$this->findingAt('src/A.php', VulnerabilityType::SQL_INJECTION, $otherStart, $otherEnd)]));
    }

    /** @return iterable<string, array{int, int}> */
    public static function touchingRanges(): iterable
    {
        yield 'ends on its first line' => [8, 10];
        yield 'starts on its last line' => [12, 14];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_finding_is_kept_when_no_other_of_its_file_and_type_overlaps_it(): void
    {
        $finding = $this->findingAt('src/A.php', VulnerabilityType::SQL_INJECTION, 10, 12);

        self::assertSame([$finding], FindingOverlap::outside([$finding], [
            $this->findingAt('src/A.php', VulnerabilityType::SQL_INJECTION, 13, 20),
            $this->findingAt('src/A.php', VulnerabilityType::XSS, 10, 12),
            $this->findingAt('src/B.php', VulnerabilityType::SQL_INJECTION, 10, 12),
        ]));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function findingAt(string $filePath, VulnerabilityType $vulnerabilityType, int $lineStart, int $lineEnd): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, VulnerabilitySeverity::HIGH, 'Finding', 0.8),
            new CodeLocation($filePath, $lineStart, $lineEnd),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
