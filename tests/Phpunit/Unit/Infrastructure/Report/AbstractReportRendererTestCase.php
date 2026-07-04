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

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;

abstract class AbstractReportRendererTestCase extends TestCase
{
    protected ReportRendererInterface $renderer;

    protected string $tmpDir;

    abstract protected function createRenderer(): ReportRendererInterface;

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/renderer_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
        $this->renderer = $this->createRenderer();
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
    }

    protected function makeReport(Vulnerability ...$vulnerabilities): AuditReport
    {
        return AuditReport::fromContext($this->buildContext(...$vulnerabilities));
    }

    protected function makeReportWithCost(AuditCost $auditCost, Vulnerability ...$vulnerabilities): AuditReport
    {
        return AuditReport::fromContext($this->buildContext(...$vulnerabilities), $auditCost);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     */
    protected function makeValidatedVuln(
        VulnerabilityType $vulnerabilityType = VulnerabilityType::SQL_INJECTION,
        VulnerabilitySeverity $vulnerabilitySeverity = VulnerabilitySeverity::HIGH,
        string $filePath = 'src/Foo.php',
        int $lineStart = 1,
    ): Vulnerability {
        return Vulnerability::of(
            new VulnerabilityClassification($vulnerabilityType, $vulnerabilitySeverity, 'Test Vuln', 0.9),
            new CodeLocation($filePath, $lineStart, $lineStart + 4),
            new VulnerabilityNarrative('Test description', 'inject', "' OR 1=1", 'fix'),
            '$q',
        )->withReviewerValidation(true);
    }

    private function buildContext(Vulnerability ...$vulnerabilities): AuditContext
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        foreach ($vulnerabilities as $vulnerability) {
            $auditContext->addVulnerability($vulnerability);
        }

        return $auditContext;
    }
}
