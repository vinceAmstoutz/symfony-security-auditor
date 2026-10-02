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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Report;

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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\RiskHeadline;

final class RiskHeadlineTest extends TestCase
{
    /**
     * @param list<string> $attackerStatuses
     *
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('runs')]
    public function test_it_states_the_risk_level_only_for_a_run_that_analyzed_a_file(array $attackerStatuses, string $expectedRiskLevel): void
    {
        self::assertSame($expectedRiskLevel, RiskHeadline::riskLevel($this->reportWithOneFinding($attackerStatuses)));
    }

    /**
     * @return iterable<string, array{list<string>, string}>
     */
    public static function runs(): iterable
    {
        yield 'a complete run' => [['analyzed'], 'LOW'];
        yield 'a partly failed run' => [['analyzed', 'errored'], 'LOW'];
        yield 'a run that analyzed no file' => [['errored', 'aborted'], 'UNKNOWN'];
    }

    /**
     * @param list<string> $attackerStatuses
     *
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('scoreDetails')]
    public function test_it_qualifies_the_score_by_what_the_run_analyzed(array $attackerStatuses, string $expectedScoreDetail): void
    {
        self::assertSame($expectedScoreDetail, RiskHeadline::scoreDetail($this->reportWithOneFinding($attackerStatuses), 'Score:'));
    }

    /**
     * @return iterable<string, array{list<string>, string}>
     */
    public static function scoreDetails(): iterable
    {
        yield 'a complete run' => [['analyzed'], 'Score: 10'];
        yield 'a partly failed run' => [['analyzed', 'errored'], 'Score: 10, on the files analyzed'];
        yield 'a run that analyzed no file' => [['errored', 'aborted'], 'no file was analyzed'];
    }

    /**
     * @param list<string> $attackerStatuses
     *
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function reportWithOneFinding(array $attackerStatuses): AuditReport
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        foreach ($attackerStatuses as $index => $status) {
            $auditContext->recordCoverage('attacker', \sprintf('src/File%d.php', $index), $status);
        }

        $auditContext->addVulnerability(Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Recovered finding', 0.9),
            new CodeLocation('src/File0.php', 1, 2),
            new VulnerabilityNarrative('Description', 'Vector', 'Proof', 'Fix'),
            '$code',
        )->withReviewerValidation(true));

        return AuditReport::fromContext($auditContext);
    }
}
