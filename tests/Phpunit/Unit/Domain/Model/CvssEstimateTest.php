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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CvssEstimate;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class CvssEstimateTest extends TestCase
{
    #[DataProvider('severityScoreCases')]
    public function test_the_base_score_is_the_representative_value_of_the_severity_band(VulnerabilitySeverity $vulnerabilitySeverity, float $expectedScore): void
    {
        self::assertSame($expectedScore, CvssEstimate::for(VulnerabilityType::SQL_INJECTION, $vulnerabilitySeverity)->baseScore());
    }

    /** @return iterable<string, array{VulnerabilitySeverity, float}> */
    public static function severityScoreCases(): iterable
    {
        yield 'critical' => [VulnerabilitySeverity::CRITICAL, 9.3];
        yield 'high' => [VulnerabilitySeverity::HIGH, 8.1];
        yield 'medium' => [VulnerabilitySeverity::MEDIUM, 5.8];
        yield 'low' => [VulnerabilitySeverity::LOW, 3.1];
        yield 'info' => [VulnerabilitySeverity::INFO, 0.0];
    }

    #[DataProvider('severityImpactCases')]
    public function test_the_impact_metrics_scale_with_severity(VulnerabilitySeverity $vulnerabilitySeverity, string $expectedImpactTriplet): void
    {
        $vector = CvssEstimate::for(VulnerabilityType::SQL_INJECTION, $vulnerabilitySeverity)->vector();

        self::assertStringContainsString($expectedImpactTriplet, $vector);
    }

    /** @return iterable<string, array{VulnerabilitySeverity, string}> */
    public static function severityImpactCases(): iterable
    {
        yield 'critical → full impact' => [VulnerabilitySeverity::CRITICAL, 'VC:H/VI:H/VA:H'];
        yield 'high → no availability' => [VulnerabilitySeverity::HIGH, 'VC:H/VI:H/VA:N'];
        yield 'medium → low impact' => [VulnerabilitySeverity::MEDIUM, 'VC:L/VI:L/VA:N'];
        yield 'low → confidentiality only' => [VulnerabilitySeverity::LOW, 'VC:L/VI:N/VA:N'];
        yield 'info → no impact' => [VulnerabilitySeverity::INFO, 'VC:N/VI:N/VA:N'];
    }

    #[DataProvider('privilegesRequiredCases')]
    public function test_privileges_required_follows_the_type_category(VulnerabilityType $vulnerabilityType, string $expectedPrivilegesMetric): void
    {
        self::assertStringContainsString($expectedPrivilegesMetric, CvssEstimate::for($vulnerabilityType, VulnerabilitySeverity::HIGH)->vector());
    }

    /** @return iterable<string, array{VulnerabilityType, string}> */
    public static function privilegesRequiredCases(): iterable
    {
        yield 'access control → authenticated' => [VulnerabilityType::MISSING_VOTER, 'PR:L'];
        yield 'logic flaw → authenticated' => [VulnerabilityType::PRICE_MANIPULATION, 'PR:L'];
        yield 'symfony-specific → authenticated' => [VulnerabilityType::MASS_ASSIGNMENT, 'PR:L'];
        yield 'injection → unauthenticated' => [VulnerabilityType::SQL_INJECTION, 'PR:N'];
        yield 'data exposure → unauthenticated' => [VulnerabilityType::SSRF, 'PR:N'];
        yield 'cryptographic → unauthenticated' => [VulnerabilityType::WEAK_CRYPTOGRAPHY, 'PR:N'];
    }

    public function test_the_vector_is_a_complete_cvss_4_0_base_string(): void
    {
        self::assertSame(
            'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
            CvssEstimate::for(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL)->vector(),
        );
    }

    public function test_to_array_carries_the_version_vector_and_base_score(): void
    {
        self::assertSame(
            [
                'version' => '4.0',
                'vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N',
                'base_score' => 8.1,
            ],
            CvssEstimate::for(VulnerabilityType::MISSING_VOTER, VulnerabilitySeverity::HIGH)->toArray(),
        );
    }

    public function test_every_vulnerability_type_produces_a_well_formed_vector(): void
    {
        foreach (VulnerabilityType::cases() as $vulnerabilityType) {
            self::assertMatchesRegularExpression(
                '#^CVSS:4\.0/AV:N/AC:L/AT:N/PR:[NL]/UI:N/VC:[HLN]/VI:[HLN]/VA:[HN]/SC:N/SI:N/SA:N$#',
                CvssEstimate::for($vulnerabilityType, VulnerabilitySeverity::HIGH)->vector(),
            );
        }
    }
}
