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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Runner;

use ReflectionException;
use ReflectionMethod;
use UnitEnum;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ExecutiveSummary;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SecurityGrade;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

/**
 * Builds the Domain models through the factories an integration uses and
 * reads them back: findings, a context in each state a report can come from
 * (no file, files and no finding, findings, a file that failed), the report,
 * its executive summary, the cost and budget objects and every enum case.
 */
final readonly class DomainModelProbe
{
    private const int DEPTH = 3;

    /**
     * @return array<string, mixed>
     *
     * @throws InvalidAuditBudgetException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidTokenUsageException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws ReflectionException
     */
    public static function snapshot(Workspace $workspace): array
    {
        $vulnerability = self::finding(VulnerabilityType::BROKEN_ACCESS_CONTROL, VulnerabilitySeverity::CRITICAL, 'Unprotected admin', 'src/Controller/AdminController.php');
        $high = self::finding(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'SQL injection in search', 'src/Controller/SearchController.php');

        $snapshot = [
            'finding' => AccessorSnapshot::of($high, self::DEPTH),
            'validatedFinding' => AccessorSnapshot::of($high->withReviewerValidation(true), self::DEPTH),
            'fingerprintOf' => Vulnerability::fingerprintOf('sql_injection', 'src/Controller/SearchController.php', 'SQL injection in search'),
            'deprecatedCreate' => AccessorSnapshot::of(self::deprecatedCreate(), self::DEPTH),
            'tokenUsage' => AccessorSnapshot::of(TokenUsageSnapshot::of(10, 5, 2, 1), self::DEPTH),
            'budgets' => AccessorSnapshot::of([AuditBudget::unlimited(), AuditBudget::forTokens(1000), AuditBudget::forCost(1.5), AuditBudget::forBoth(1000, 1.5)], self::DEPTH),
            'costs' => AccessorSnapshot::of([AuditCost::zero('gpt-4o'), AuditCost::of(1000, 100, 0.5, 'gpt-4o')], self::DEPTH),
            'riskLevels' => self::cases(RiskLevel::cases()),
            'grades' => self::cases(SecurityGrade::cases()),
            'severities' => self::cases(VulnerabilitySeverity::cases()),
            'types' => self::cases(VulnerabilityType::cases()),
        ];

        foreach (self::contexts($workspace, $vulnerability, $high) as $name => $auditContext) {
            $auditReport = AuditReport::fromContext($auditContext, AuditCost::of(1000, 100, 0.5, 'gpt-4o'));
            $snapshot[\sprintf('context:%s', $name)] = AccessorSnapshot::of($auditContext, self::DEPTH);
            $snapshot[\sprintf('report:%s', $name)] = AccessorSnapshot::of($auditReport, self::DEPTH);
            $snapshot[\sprintf('summary:%s', $name)] = AccessorSnapshot::of(ExecutiveSummary::of($auditReport), self::DEPTH);
        }

        return $snapshot;
    }

    /**
     * @return array<string, AuditContext>
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private static function contexts(Workspace $workspace, Vulnerability $critical, Vulnerability $high): array
    {
        $projectDir = $workspace->projectDir();
        $files = [
            ProjectFile::create('src/Controller/AdminController.php', \sprintf('%s/src/Controller/AdminController.php', $projectDir), "<?php\nclass AdminController {}\n"),
            ProjectFile::create('src/Controller/SearchController.php', \sprintf('%s/src/Controller/SearchController.php', $projectDir), "<?php\nclass SearchController {}\n"),
        ];

        $auditContext = AuditContext::forProject($projectDir);

        $clean = AuditContext::forProject($projectDir);
        $clean->setProjectFiles($files);

        $findings = AuditContext::forProject($projectDir, ['src'], false, null, [$high->fingerprint()]);
        $findings->setProjectFiles($files);
        $findings->addVulnerability($critical->withReviewerValidation(true));
        $findings->addVulnerability($high);

        $failed = AuditContext::forProject($projectDir);
        $failed->setProjectFiles($files);
        $failed->recordCoverage('attacker', 'src/Controller/AdminController.php', 'errored');
        $failed->recordCoverage('attacker', 'src/Controller/SearchController.php', 'analyzed');

        return ['no-file' => $auditContext, 'clean' => $clean, 'findings' => $findings, 'failed-file' => $failed];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private static function finding(VulnerabilityType $vulnerabilityType, VulnerabilitySeverity $vulnerabilitySeverity, string $title, string $filePath): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, $vulnerabilitySeverity, $title, 0.9),
            new CodeLocation($filePath, 7, 9),
            new VulnerabilityNarrative('description', 'attack vector', 'proof', 'remediation'),
            'vulnerable code',
        );
    }

    /**
     * `Vulnerability::create()` is deprecated, and still public API until
     * 2.0: the probe calls it the way an integration written for an older
     * release does.
     *
     * @throws ReflectionException
     */
    private static function deprecatedCreate(): mixed
    {
        return (new ReflectionMethod(Vulnerability::class, 'create'))->invoke(null, VulnerabilityType::XXE, VulnerabilitySeverity::MEDIUM, 'XXE', 'd', 'src/Xml.php', 3, 4, 'code', 'vector', 'proof', 'fix', 0.8);
    }

    /**
     * @param list<UnitEnum> $cases
     *
     * @return array<string, mixed>
     */
    private static function cases(array $cases): array
    {
        $snapshot = [];
        foreach ($cases as $case) {
            $snapshot[$case->name] = AccessorSnapshot::accessorsOf($case, self::DEPTH);
        }

        return $snapshot;
    }
}
