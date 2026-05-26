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

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Style\SymfonyStyle;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;

final class AuditPresenterTest extends TestCase
{
    private AuditPresenter $auditPresenter;

    private string $tmpDir;

    protected function setUp(): void
    {
        $this->auditPresenter = new AuditPresenter();
        $this->tmpDir = sys_get_temp_dir().'/presenter_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        rmdir($this->tmpDir);
    }

    public function test_error_for_invalid_argument_exception_uses_message_as_is(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->error($symfonyStyle, new InvalidArgumentException('Project path missing'));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Project path missing', $display);
        self::assertStringNotContainsString('Unexpected error:', $display);
    }

    public function test_error_for_generic_throwable_prefixes_message_with_unexpected_error(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->error($symfonyStyle, new RuntimeException('Disk full'));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Unexpected error: Disk full', $display);
    }

    public function test_header_includes_project_path(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->header($symfonyStyle, '/path/to/project');

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Project:', $display);
        self::assertStringContainsString('/path/to/project', $display);
        self::assertStringContainsString('Pipeline:', $display);
    }

    public function test_result_for_failure_exit_omits_success_message(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->result($symfonyStyle, $this->makeCriticalReport(), Command::FAILURE);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('CRITICAL', $display);
        self::assertStringContainsString('vulnerabilities found', $display);
        self::assertStringNotContainsString('Audit complete. Risk:', $display);
    }

    public function test_result_for_success_exit_emits_success_message(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->result($symfonyStyle, AuditReport::fromContext(AuditContext::forProject($this->tmpDir)), Command::SUCCESS);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Audit complete. Risk:', $display);
        self::assertStringNotContainsString('CRITICAL risk level', $display);
    }

    public function test_running_section_emits_section_header(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->runningSection($symfonyStyle);

        self::assertStringContainsString('Running audit pipeline', $bufferedOutput->fetch());
    }

    public function test_estimating_section_emits_dry_run_section_header(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->estimatingSection($symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('dry run', $display);
        self::assertStringNotContainsString('Running audit pipeline', $display);
    }

    public function test_dry_run_result_shows_completion_without_audit_language(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->dryRunResult($symfonyStyle, AuditReport::fromContext(AuditContext::forProject($this->tmpDir)));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('Dry run complete', $display);
        self::assertStringContainsString('no LLM calls', $display);
        self::assertStringNotContainsString('Audit complete', $display);
        self::assertStringNotContainsString('RISK LEVEL', $display);
        self::assertStringNotContainsString('vulnerabilities found', $display);
    }

    public function test_dry_run_result_shows_cost_breakdown_when_cost_present(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $report = AuditReport::fromContext($auditContext, AuditCost::of(1000, 200, 0.0123, 'claude-opus-4-7'));

        $this->auditPresenter->dryRunResult($symfonyStyle, $report);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('claude-opus-4-7', $display);
        self::assertStringContainsString('1,000', $display);
        self::assertStringContainsString('0.0123', $display);
    }

    private function makeCriticalReport(): AuditReport
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

        return AuditReport::fromContext($auditContext);
    }
}
