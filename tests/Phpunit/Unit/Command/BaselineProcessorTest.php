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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessor;

final class BaselineProcessorTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/baseline_processor_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
    }

    public function test_generate_writes_the_report_fingerprints_and_returns_their_count(): void
    {
        $auditReport = $this->makeReport($this->makeVuln('src/A.php'), $this->makeVuln('src/B.php'));

        $baseline = $this->createMock(BaselineInterface::class);
        $baseline->expects(self::once())
            ->method('save')
            ->with('/out/baseline.json', $auditReport->fingerprints());

        $count = (new BaselineProcessor($baseline))->generate($auditReport, '/out/baseline.json');

        self::assertSame(2, $count);
    }

    public function test_apply_returns_the_report_unchanged_when_no_baseline_path_is_set(): void
    {
        $auditReport = $this->makeReport($this->makeVuln('src/A.php'));

        $baseline = $this->createMock(BaselineInterface::class);
        $baseline->expects(self::never())->method('load');

        $baselineResult = (new BaselineProcessor($baseline))->apply($auditReport, null);

        self::assertSame($auditReport, $baselineResult->report);
        self::assertSame(0, $baselineResult->suppressedCount);
    }

    public function test_apply_suppresses_matching_findings_and_reports_the_suppressed_count(): void
    {
        $vulnerability = $this->makeVuln('src/Keep.php');
        $dropped = $this->makeVuln('src/Drop.php');
        $auditReport = $this->makeReport($vulnerability, $dropped);

        $baseline = $this->createMock(BaselineInterface::class);
        $baseline->method('load')->willReturn([$dropped->fingerprint()]);

        $baselineResult = (new BaselineProcessor($baseline))->apply($auditReport, '/baseline.json');

        self::assertSame(1, $baselineResult->report->totalVulnerabilities());
        self::assertSame($vulnerability->fingerprint(), $baselineResult->report->vulnerabilities()[0]->fingerprint());
        self::assertSame(1, $baselineResult->suppressedCount);
    }

    public function test_apply_prefers_the_cli_baseline_over_the_configured_path(): void
    {
        $auditReport = $this->makeReport($this->makeVuln('src/A.php'));

        $baseline = $this->createMock(BaselineInterface::class);
        $baseline->expects(self::once())
            ->method('load')
            ->with('/cli.json')
            ->willReturn([]);

        $baselineResult = (new BaselineProcessor($baseline, '/configured.json'))->apply($auditReport, '/cli.json');

        self::assertSame(0, $baselineResult->suppressedCount);
    }

    public function test_apply_falls_back_to_the_configured_path_when_no_cli_override(): void
    {
        $auditReport = $this->makeReport($this->makeVuln('src/A.php'));

        $baseline = $this->createMock(BaselineInterface::class);
        $baseline->expects(self::once())
            ->method('load')
            ->with('/configured.json')
            ->willReturn([]);

        $baselineResult = (new BaselineProcessor($baseline, '/configured.json'))->apply($auditReport, null);

        self::assertSame(1, $baselineResult->report->totalVulnerabilities());
    }

    private function makeReport(Vulnerability ...$vulnerabilities): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        foreach ($vulnerabilities as $vulnerability) {
            $auditContext->addVulnerability($vulnerability);
        }

        return AuditReport::fromContext($auditContext);
    }

    private function makeVuln(string $filePath): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'Finding '.$filePath, 0.9),
            new CodeLocation($filePath, 1, 5),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            'code',
        )->withReviewerValidation(true);
    }
}
