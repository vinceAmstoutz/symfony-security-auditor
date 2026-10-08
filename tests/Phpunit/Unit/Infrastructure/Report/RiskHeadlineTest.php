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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
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
     * @throws InvalidProjectFileException
     */
    #[DataProvider('runs')]
    public function test_it_states_the_risk_level_of_every_run_that_reached_a_verdict(array $attackerStatuses, bool $holdsAFinding, string $expectedRiskLevel): void
    {
        self::assertSame($expectedRiskLevel, RiskHeadline::riskLevel($this->report($attackerStatuses, $holdsAFinding)));
    }

    /**
     * @return iterable<string, array{list<string>, bool, string}>
     */
    public static function runs(): iterable
    {
        yield 'a complete run' => [['analyzed'], true, 'LOW'];
        yield 'a partly failed run' => [['analyzed', 'errored'], true, 'LOW'];
        yield 'a run that analyzed no file yet holds a finding' => [['errored', 'aborted'], true, 'LOW'];
        yield 'a run that analyzed no file and found nothing' => [['errored', 'aborted'], false, 'UNKNOWN'];
        yield 'a scan that found no file' => [[], false, 'UNKNOWN'];
    }

    /**
     * @param list<string> $attackerStatuses
     *
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('scoreDetails')]
    public function test_it_qualifies_the_score_by_what_the_run_analyzed(array $attackerStatuses, bool $holdsAFinding, string $expectedScoreDetail): void
    {
        self::assertSame($expectedScoreDetail, RiskHeadline::scoreDetail($this->report($attackerStatuses, $holdsAFinding), 'Score:'));
    }

    /**
     * @return iterable<string, array{list<string>, bool, string}>
     */
    public static function scoreDetails(): iterable
    {
        yield 'a complete run' => [['analyzed'], true, 'Score: 10'];
        yield 'a partly failed run' => [['analyzed', 'errored'], true, 'Score: 10, on the files analyzed'];
        yield 'a run that analyzed no file yet holds a finding' => [['errored', 'aborted'], true, 'Score: 10, on the files analyzed'];
        yield 'a run that analyzed no file and found nothing' => [['errored', 'aborted'], false, 'no file was analyzed'];
        yield 'a scan that found no file' => [[], false, 'no file was analyzed'];
    }

    /**
     * @param list<string> $attackerStatuses
     *
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws InvalidProjectFileException
     */
    private function report(array $attackerStatuses, bool $holdsAFinding): AuditReport
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $files = [];
        foreach ($attackerStatuses as $index => $status) {
            $path = \sprintf('src/File%d.php', $index);
            $files[] = ProjectFile::create($path, sys_get_temp_dir().'/'.$path, '<?php');
            $auditContext->recordCoverage('attacker', $path, $status);
        }

        $auditContext->setProjectFiles($files);

        if ($holdsAFinding) {
            $auditContext->addVulnerability(Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Recovered finding', 0.9),
                new CodeLocation('src/File0.php', 1, 2),
                new VulnerabilityNarrative('Description', 'Vector', 'Proof', 'Fix'),
                '$code',
            )->withReviewerValidation(true));
        }

        return AuditReport::fromContext($auditContext);
    }
}
