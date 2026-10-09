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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;

final class FindingTypeFilterTest extends TestCase
{
    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/type_filter_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_apply_without_configured_types_keeps_all_findings(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::SQL_INJECTION, VulnerabilityType::SSRF);

        self::assertSame(2, (new FindingTypeFilter())->apply($auditReport)->totalVulnerabilities());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_apply_excludes_configured_type_values(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::SQL_INJECTION, VulnerabilityType::SSRF);

        $filtered = (new FindingTypeFilter(excludedTypeValues: ['sql_injection']))->apply($auditReport);

        self::assertSame([VulnerabilityType::SSRF], $this->typesOf($filtered));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_apply_restricts_to_included_type_values(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::SQL_INJECTION, VulnerabilityType::SSRF, VulnerabilityType::MISSING_RATE_LIMITING);

        $filtered = (new FindingTypeFilter(includedTypeValues: ['ssrf']))->apply($auditReport);

        self::assertSame([VulnerabilityType::SSRF], $this->typesOf($filtered));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('legacySpellingsOfXss')]
    public function test_apply_mutes_an_xss_finding_under_the_type_it_was_reported_as_before_xss_existed(string $legacyTypeValue): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::XSS, VulnerabilityType::SSRF);

        $filtered = (new FindingTypeFilter(excludedTypeValues: [$legacyTypeValue]))->apply($auditReport);

        self::assertSame([VulnerabilityType::SSRF], $this->typesOf($filtered));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('legacySpellingsOfXss')]
    public function test_apply_keeps_an_xss_finding_under_an_allowlist_naming_the_type_it_was_reported_as_before(string $legacyTypeValue): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::XSS, VulnerabilityType::SSRF);

        $filtered = (new FindingTypeFilter(includedTypeValues: [$legacyTypeValue]))->apply($auditReport);

        self::assertSame([VulnerabilityType::XSS], $this->typesOf($filtered));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_apply_mutes_an_xss_finding_named_by_its_own_type(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::XSS, VulnerabilityType::SSRF);

        $filtered = (new FindingTypeFilter(excludedTypeValues: ['xss']))->apply($auditReport);

        self::assertSame([VulnerabilityType::SSRF], $this->typesOf($filtered));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('legacySpellingsOfXss')]
    public function test_apply_does_not_mute_a_legacy_typed_finding_for_an_xss_entry(string $legacyTypeValue): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::from($legacyTypeValue), VulnerabilityType::SSRF);

        $filtered = (new FindingTypeFilter(excludedTypeValues: ['xss']))->apply($auditReport);

        self::assertSame([VulnerabilityType::from($legacyTypeValue), VulnerabilityType::SSRF], $this->typesOf($filtered));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_apply_lets_an_exclusion_of_xss_win_over_an_allowlist_naming_its_legacy_type(): void
    {
        $auditReport = $this->reportWithTypes(VulnerabilityType::XSS, VulnerabilityType::TWIG_INJECTION);

        $filtered = (new FindingTypeFilter(includedTypeValues: ['twig_injection'], excludedTypeValues: ['xss']))->apply($auditReport);

        self::assertSame([VulnerabilityType::TWIG_INJECTION], $this->typesOf($filtered));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function legacySpellingsOfXss(): iterable
    {
        yield 'twig_injection' => ['twig_injection'];
        yield 'sensitive_data_exposure' => ['sensitive_data_exposure'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function reportWithTypes(VulnerabilityType ...$types): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        foreach ($types as $index => $type) {
            $auditContext->addVulnerability(
                Vulnerability::of(
                    new VulnerabilityClassification($type, VulnerabilitySeverity::HIGH, 'Vuln '.$index, 0.9),
                    new CodeLocation('src/File'.$index.'.php', 1, 5),
                    new VulnerabilityNarrative('desc', 'inject', "' OR 1", 'fix'),
                    '$q',
                )->withReviewerValidation(true),
            );
        }

        return AuditReport::fromContext($auditContext);
    }

    /**
     * @return list<VulnerabilityType>
     */
    private function typesOf(AuditReport $auditReport): array
    {
        return array_map(
            static fn (Vulnerability $vulnerability): VulnerabilityType => $vulnerability->type(),
            $auditReport->vulnerabilities(),
        );
    }
}
