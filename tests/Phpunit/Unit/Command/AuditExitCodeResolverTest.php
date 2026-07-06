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
use Symfony\Component\Console\Command\Command;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;

final class AuditExitCodeResolverTest extends TestCase
{
    private AuditExitCodeResolver $auditExitCodeResolver;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->auditExitCodeResolver = new AuditExitCodeResolver();
        $this->tmpDir = sys_get_temp_dir().'/resolver_test_'.uniqid('', true);
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
     */
    #[DataProvider('thresholdCases')]
    public function test_it_fails_only_when_risk_level_meets_the_threshold(int $criticalFindings, RiskLevel $riskLevel, int $expectedExitCode): void
    {
        $auditReport = $this->reportWith($criticalFindings);

        self::assertSame($expectedExitCode, $this->auditExitCodeResolver->resolve($auditReport, $riskLevel));
    }

    /**
     * Each critical finding scores 10, so the count maps to a risk level:
     * 0 → SAFE, 1 → LOW (10), 2 → MEDIUM (20), 4 → HIGH (40), 5 → CRITICAL (50).
     *
     * @return iterable<string, array{int, RiskLevel, int}>
     */
    public static function thresholdCases(): iterable
    {
        yield 'critical risk fails the default critical gate' => [5, RiskLevel::Critical, Command::FAILURE];
        yield 'high risk passes the default critical gate' => [4, RiskLevel::Critical, Command::SUCCESS];
        yield 'safe risk passes the default critical gate' => [0, RiskLevel::Critical, Command::SUCCESS];

        yield 'high risk fails the high gate' => [4, RiskLevel::High, Command::FAILURE];
        yield 'critical risk fails the high gate' => [5, RiskLevel::High, Command::FAILURE];
        yield 'medium risk passes the high gate' => [2, RiskLevel::High, Command::SUCCESS];

        yield 'medium risk fails the medium gate' => [2, RiskLevel::Medium, Command::FAILURE];
        yield 'low risk passes the medium gate' => [1, RiskLevel::Medium, Command::SUCCESS];

        yield 'low risk fails the low gate' => [1, RiskLevel::Low, Command::FAILURE];
        yield 'safe risk passes the low gate' => [0, RiskLevel::Low, Command::SUCCESS];

        yield 'safe risk fails the safe gate' => [0, RiskLevel::Safe, Command::FAILURE];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     */
    private function reportWith(int $criticalFindings): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        for ($i = 1; $i <= $criticalFindings; ++$i) {
            $auditContext->addVulnerability(
                Vulnerability::of(
                    new VulnerabilityClassification(
                        VulnerabilityType::SQL_INJECTION,
                        VulnerabilitySeverity::CRITICAL,
                        'Critical vuln '.$i,
                        0.9,
                    ),
                    new CodeLocation('src/File'.$i.'.php', 1, 5),
                    new VulnerabilityNarrative('desc', 'inject', "' OR 1", 'fix'),
                    '$q',
                )->withReviewerValidation(true),
            );
        }

        return AuditReport::fromContext($auditContext);
    }
}
