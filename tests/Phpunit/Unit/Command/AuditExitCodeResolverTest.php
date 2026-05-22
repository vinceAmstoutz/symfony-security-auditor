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

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;

final class AuditExitCodeResolverTest extends TestCase
{
    private AuditExitCodeResolver $auditExitCodeResolver;

    private string $tmpDir;

    protected function setUp(): void
    {
        $this->auditExitCodeResolver = new AuditExitCodeResolver();
        $this->tmpDir = sys_get_temp_dir().'/resolver_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    public function test_it_returns_failure_for_critical_risk_level(): void
    {
        $auditReport = AuditReport::fromContext($this->criticalContext());

        self::assertSame(Command::FAILURE, $this->auditExitCodeResolver->resolve($auditReport));
    }

    public function test_it_returns_success_for_safe_risk_level(): void
    {
        $auditReport = AuditReport::fromContext(AuditContext::forProject($this->tmpDir));

        self::assertSame(Command::SUCCESS, $this->auditExitCodeResolver->resolve($auditReport));
    }

    public function test_it_returns_success_for_high_risk_level(): void
    {
        // HIGH = score >= 30 and < 50; 5 HIGH vulns = 35
        $auditContext = AuditContext::forProject($this->tmpDir);
        for ($i = 1; $i <= 5; ++$i) {
            $auditContext->addVulnerability(
                Vulnerability::create(
                    VulnerabilityType::SQL_INJECTION,
                    VulnerabilitySeverity::HIGH,
                    'High vuln '.$i,
                    'desc',
                    'src/File'.$i.'.php',
                    1, 5, '$q', 'inject', "' OR 1", 'fix', 0.9,
                )->withReviewerValidation(true),
            );
        }

        $auditReport = AuditReport::fromContext($auditContext);

        self::assertSame('HIGH', $auditReport->riskLevel());
        self::assertSame(Command::SUCCESS, $this->auditExitCodeResolver->resolve($auditReport));
    }

    private function criticalContext(): AuditContext
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        for ($i = 1; $i <= 5; ++$i) {
            $auditContext->addVulnerability(
                Vulnerability::create(
                    VulnerabilityType::SQL_INJECTION,
                    VulnerabilitySeverity::CRITICAL,
                    'Critical vuln '.$i,
                    'desc',
                    'src/File'.$i.'.php',
                    1, 5, '$q', 'inject', "' OR 1", 'fix', 0.9,
                )->withReviewerValidation(true),
            );
        }

        return $auditContext;
    }
}
