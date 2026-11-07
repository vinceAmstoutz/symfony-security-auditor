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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Critic;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic\FindingsOnlyCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

final class FindingsOnlyCoverageRecorderTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_leaves_the_coverage_ledger_of_the_run_untouched(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());

        (new FindingsOnlyCoverageRecorder($auditContext))->recordCoverage('attacker', 'src/Controller/A.php', 'errored');

        self::assertSame([], $auditContext->coverage());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_found_vulnerability_reaches_the_run(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $vulnerability = $this->vulnerability();

        (new FindingsOnlyCoverageRecorder($auditContext))->recordFoundVulnerability($vulnerability);

        self::assertSame([$vulnerability], $auditContext->drainFoundVulnerabilities());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_drains_the_vulnerabilities_the_run_holds(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $vulnerability = $this->vulnerability();
        $auditContext->recordFoundVulnerability($vulnerability);

        self::assertSame([$vulnerability], (new FindingsOnlyCoverageRecorder($auditContext))->drainFoundVulnerabilities());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_reviewed_finding_reaches_the_run(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $vulnerability = $this->vulnerability();

        (new FindingsOnlyCoverageRecorder($auditContext))->recordReviewedFinding($vulnerability);

        self::assertSame([$vulnerability], $auditContext->drainReviewedFindings());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_it_drains_the_reviewed_findings_the_run_holds(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $vulnerability = $this->vulnerability();
        $auditContext->recordReviewedFinding($vulnerability);

        self::assertSame([$vulnerability], (new FindingsOnlyCoverageRecorder($auditContext))->drainReviewedFindings());
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerability(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::HIGH, 'Bulk export without owner check', 0.9),
            new CodeLocation('src/Controller/A.php', 1, 2),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
