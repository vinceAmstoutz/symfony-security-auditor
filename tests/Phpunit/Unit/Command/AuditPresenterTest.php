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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;

final class AuditPresenterTest extends TestCase
{
    private AuditPresenter $auditPresenter;

    private string $tmpDir;

    protected function setUp(): void
    {
        $this->auditPresenter = new AuditPresenter($this->pricingProviderKnowing('claude-opus-4-7', 'claude-haiku-4-5-20251001'));
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

    public function test_long_run_notice_warns_that_the_audit_can_take_a_while(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->longRunNotice($symfonyStyle);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('many LLM calls', $display);
        self::assertStringContainsString('20+ minutes', $display);
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

    public function test_preflight_warnings_emit_secret_scrubbing_warning_when_disabled(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->preflightWarnings($symfonyStyle, secretScrubbingEnabled: false);

        $display = $bufferedOutput->fetch();
        $flattened = preg_replace('/\s+/', ' ', $display) ?? '';
        self::assertStringContainsString('Secret scrubbing is disabled. File contents will be sent verbatim to the configured LLM provider.', $flattened);
        self::assertStringContainsString('If that provider runs in the cloud, credentials in committed configs or .env.dist files may be exposed.', $flattened);
        self::assertStringContainsString('Re-enable scan.secret_scrubbing.enabled (the default) or confirm you are using a local provider.', $flattened);
    }

    public function test_preflight_warnings_are_silent_when_secret_scrubbing_enabled(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->preflightWarnings($symfonyStyle, secretScrubbingEnabled: true);

        self::assertSame('', $bufferedOutput->fetch());
    }

    public function test_preflight_warnings_print_each_config_notice(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->preflightWarnings($symfonyStyle, secretScrubbingEnabled: true, configNotices: [
            'first notice about the cache',
            'second notice about batching',
        ]);

        $flattened = preg_replace('/\s+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringContainsString('first notice about the cache', $flattened);
        self::assertStringContainsString('second notice about batching', $flattened);
    }

    public function test_baseline_generated_reports_the_path_and_count(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->baselineGenerated($symfonyStyle, '.security-baseline.json', 3);

        $flattened = preg_replace('/\s+/', ' ', $bufferedOutput->fetch()) ?? '';
        self::assertStringContainsString('Baseline written to .security-baseline.json', $flattened);
        self::assertStringContainsString('3 finding fingerprint(s)', $flattened);
    }

    public function test_baseline_applied_reports_the_suppressed_count(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->baselineApplied($symfonyStyle, 2);

        self::assertStringContainsString('2 finding(s) suppressed by the baseline.', $bufferedOutput->fetch());
    }

    public function test_baseline_applied_reports_a_single_suppression(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->baselineApplied($symfonyStyle, 1);

        self::assertStringContainsString('1 finding(s) suppressed by the baseline.', $bufferedOutput->fetch());
    }

    public function test_baseline_applied_is_silent_when_nothing_suppressed(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->baselineApplied($symfonyStyle, 0);

        self::assertSame('', $bufferedOutput->fetch());
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
        $flattened = preg_replace('/[\s!]+/', ' ', $display) ?? '';
        self::assertStringContainsString('Dry run complete', $flattened);
        self::assertStringContainsString('a real run typically costs less', $flattened);
        self::assertStringContainsString('no LLM calls', $flattened);
        self::assertStringNotContainsString('Audit complete', $display);
        self::assertStringNotContainsString('RISK LEVEL', $display);
        self::assertStringNotContainsString('vulnerabilities found', $display);
    }

    public function test_dry_run_result_shows_cost_breakdown_when_cost_present(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditReport = AuditReport::fromContext($auditContext, AuditCost::of(1000, 200, 0.0123, 'claude-opus-4-7'));

        $this->auditPresenter->dryRunResult($symfonyStyle, $auditReport);

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('claude-opus-4-7', $display);
        self::assertStringContainsString('1,000', $display);
        self::assertStringContainsString('0.0123', $display);
    }

    public function test_unsupported_model_warning_names_every_unsupported_model(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $this->reportWithRoleModels('made-up-attacker-model', 'made-up-reviewer-model'));

        $display = $bufferedOutput->fetch();
        self::assertStringContainsString('made-up-attacker-model', $display);
        self::assertStringContainsString('made-up-reviewer-model', $display);
    }

    public function test_unsupported_model_warning_ignores_supported_models(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $this->reportWithRoleModels('made-up-attacker-model', 'claude-opus-4-7'));

        self::assertStringNotContainsString('claude-opus-4-7', $bufferedOutput->fetch());
    }

    public function test_unsupported_model_warning_is_silent_when_all_models_supported(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $this->reportWithRoleModels('claude-opus-4-7', 'claude-haiku-4-5-20251001'));

        self::assertSame('', $bufferedOutput->fetch());
    }

    public function test_unsupported_model_warning_is_silent_when_no_models_present(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, AuditReport::fromContext(AuditContext::forProject($this->tmpDir)));

        self::assertSame('', $bufferedOutput->fetch());
    }

    public function test_unsupported_model_warning_names_a_shared_model_only_once(): void
    {
        $bufferedOutput = new BufferedOutput();
        $symfonyStyle = new SymfonyStyle(new StringInput(''), $bufferedOutput);

        $this->auditPresenter->unsupportedModelWarnings($symfonyStyle, $this->reportWithRoleModels('made-up-model', 'made-up-model'));

        self::assertSame(1, substr_count($bufferedOutput->fetch(), 'made-up-model'));
    }

    private function reportWithRoleModels(string $attackerModel, string $reviewerModel): AuditReport
    {
        $auditCost = AuditCost::of(1000, 200, 0.0, $attackerModel, [
            'attacker' => ['model' => $attackerModel, 'input_tokens' => 800, 'output_tokens' => 150, 'estimated_cost_usd' => 0.0],
            'reviewer' => ['model' => $reviewerModel, 'input_tokens' => 200, 'output_tokens' => 50, 'estimated_cost_usd' => 0.0],
        ]);

        return AuditReport::fromContext(AuditContext::forProject($this->tmpDir), $auditCost);
    }

    private function pricingProviderKnowing(string ...$supportedModels): PricingProviderInterface
    {
        return new class($supportedModels) implements PricingProviderInterface {
            /** @param array<string> $supportedModels */
            public function __construct(private array $supportedModels) {}

            public function pricePerMillionInputTokens(string $model): float
            {
                return 0.0;
            }

            public function pricePerMillionOutputTokens(string $model): float
            {
                return 0.0;
            }

            public function hasModel(string $model): bool
            {
                return \in_array($model, $this->supportedModels, true);
            }
        };
    }

    private function makeCriticalReport(): AuditReport
    {
        $auditContext = AuditContext::forProject($this->tmpDir);
        for ($i = 1; $i <= 5; ++$i) {
            $auditContext->addVulnerability(
                Vulnerability::of(
                    new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::CRITICAL, 'Critical vuln '.$i, 0.9),
                    new CodeLocation('src/File'.$i.'.php', 1, 5),
                    new VulnerabilityNarrative('desc', 'inject', "' OR 1", 'fix'),
                    '$q',
                )->withReviewerValidation(true),
            );
        }

        return AuditReport::fromContext($auditContext);
    }
}
