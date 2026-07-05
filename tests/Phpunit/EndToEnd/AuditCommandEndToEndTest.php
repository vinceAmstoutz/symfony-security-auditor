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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\EndToEnd;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerLlmCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerScanCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditLoopSettings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgentCollaborators;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerModeConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\ListScannedFilesUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ConsoleReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\HtmlReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JunitReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\MarkdownReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineProcessor;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ExitCode;
use VinceAmstoutz\SymfonySecurityAuditor\Command\FindingTypeFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\UnpricedModelBudgetGuard;

final class AuditCommandEndToEndTest extends TestCase
{
    private string $fixtureDir;

    public function test_command_exits_success_for_safe_project(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function test_command_output_contains_risk_level(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringContainsString('SAFE', $commandTester->getDisplay());
    }

    public function test_command_streams_a_coherent_attacker_then_reviewer_then_report_narrative(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        $display = $commandTester->getDisplay();
        self::assertStringContainsString('Auditing', $display);
        self::assertStringContainsString('[CRITICAL] sql_injection', $display);
        self::assertStringContainsString('[VALIDATED] sql_injection', $display);
        self::assertStringContainsString('5 validated, 0 rejected', $display);
        self::assertStringContainsString('SYMFONY LLM AUDIT REPORT', $display);

        $attackerStreamPosition = mb_strpos($display, '[CRITICAL] sql_injection');
        $reviewerStreamPosition = mb_strpos($display, '[VALIDATED] sql_injection');
        $reportPosition = mb_strpos($display, 'SYMFONY LLM AUDIT REPORT');
        self::assertIsInt($attackerStreamPosition);
        self::assertIsInt($reviewerStreamPosition);
        self::assertIsInt($reportPosition);
        self::assertLessThan($reviewerStreamPosition, $attackerStreamPosition);
        self::assertLessThan($reportPosition, $reviewerStreamPosition);
    }

    public function test_command_streams_rejected_verdicts_in_the_output_when_the_reviewer_rejects(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": false}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        $display = $commandTester->getDisplay();
        self::assertStringContainsString('[CRITICAL] sql_injection', $display);
        self::assertStringContainsString('[REJECTED] sql_injection', $display);
        self::assertStringContainsString('0 validated, 5 rejected', $display);
    }

    public function test_command_emits_secret_scrubbing_warning_when_scrubbing_disabled(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}', ['secretScrubbingEnabled' => false]);
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringContainsString('Secret scrubbing is disabled', $commandTester->getDisplay());
    }

    public function test_command_is_silent_about_scrubbing_when_enabled(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}', ['secretScrubbingEnabled' => true]);
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringNotContainsString('Secret scrubbing is disabled', $commandTester->getDisplay());
    }

    public function test_command_fails_closed_when_a_cost_budget_is_set_but_the_model_is_unpriced(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}', ['maxCostUsd' => 10.0]);
        $commandTester->execute(['project-path' => $this->fixtureDir], ['interactive' => false]);

        self::assertSame(ExitCode::BudgetAborted->value, $commandTester->getStatusCode());
        self::assertStringContainsString('non-interactive', $commandTester->getDisplay());
    }

    public function test_command_warns_on_a_real_run_when_a_configured_model_is_unpriced(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('No published pricing', $commandTester->getDisplay());
    }

    public function test_command_still_emits_scrubbing_warning_for_machine_readable_output_on_stderr(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}', ['secretScrubbingEnabled' => false]);
        $commandTester->execute(
            [
                'project-path' => $this->fixtureDir,
                '--format' => 'json',
            ],
            ['capture_stderr_separately' => true],
        );

        self::assertStringContainsString('Secret scrubbing is disabled', $commandTester->getErrorOutput());
        self::assertStringNotContainsString('Secret scrubbing is disabled', $commandTester->getDisplay());
    }

    public function test_command_exits_failure_for_nonexistent_project_path(): void
    {
        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => '/nonexistent/path/that/does/not/exist']);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
    }

    public function test_command_json_format_outputs_valid_json(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        $output = $commandTester->getDisplay();
        preg_match('/(\{.*\})/s', $output, $matches);
        $decoded = json_decode($matches[1] ?? '', true);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('audit_id', $decoded);
        self::assertArrayHasKey('risk_level', $decoded);
    }

    public function test_command_sarif_format_outputs_valid_sarif(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'sarif',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        $output = $commandTester->getDisplay();
        preg_match('/(\{.*\})/s', $output, $matches);
        $decoded = json_decode($matches[1] ?? '', true);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('version', $decoded);
        self::assertSame('2.1.0', $decoded['version']);
        self::assertArrayHasKey('runs', $decoded);
    }

    public function test_command_html_format_outputs_an_html_document(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'html',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        $output = $commandTester->getDisplay();
        self::assertStringContainsString('<!doctype html>', $output);
        self::assertStringContainsString('Security Audit Report', $output);
    }

    public function test_command_markdown_format_outputs_a_markdown_report(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'markdown',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('# Security Audit Report', $commandTester->getDisplay());
    }

    public function test_generate_baseline_writes_fingerprints_and_exits_zero_despite_critical_findings(): void
    {
        $this->createProjectDir();
        $baselineFile = $this->fixtureDir.'/baseline.json';

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $baselineFile,
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertFileExists($baselineFile);
        $fingerprints = json_decode((string) file_get_contents($baselineFile), true);
        self::assertIsArray($fingerprints);
        self::assertCount(5, $fingerprints);

        $display = $commandTester->getDisplay();
        self::assertStringContainsString('Baseline written to', $display);
        self::assertStringContainsString('SYMFONY LLM AUDIT REPORT', $display);
    }

    public function test_generate_baseline_collects_every_finding_even_when_a_baseline_is_already_configured(): void
    {
        $this->createProjectDir();
        $seedBaseline = $this->fixtureDir.'/configured.json';
        $regenerated = $this->fixtureDir.'/regenerated.json';

        $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}')->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $seedBaseline,
        ]);
        $seedEntries = json_decode((string) file_get_contents($seedBaseline), true);
        self::assertIsArray($seedEntries);
        $firstEntry = $seedEntries[0];
        self::assertIsArray($firstEntry);
        $firstFingerprint = $firstEntry['fingerprint'] ?? null;
        self::assertIsString($firstFingerprint);
        (new Baseline())->save($seedBaseline, [['fingerprint' => $firstFingerprint]]);

        $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}', ['configuredBaseline' => $seedBaseline])->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $regenerated,
        ]);

        $regeneratedEntries = json_decode((string) file_get_contents($regenerated), true);
        self::assertIsArray($regeneratedEntries);
        self::assertCount(5, $regeneratedEntries);
    }

    public function test_baseline_reports_the_exact_number_of_suppressed_findings(): void
    {
        $this->createProjectDir();
        $baselineFile = $this->fixtureDir.'/baseline.json';

        $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}')->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $baselineFile,
        ]);

        $entries = json_decode((string) file_get_contents($baselineFile), true);
        self::assertIsArray($entries);
        $partialBaseline = [];
        foreach ([$entries[0], $entries[1]] as $entry) {
            self::assertIsArray($entry);
            $fingerprint = $entry['fingerprint'] ?? null;
            self::assertIsString($fingerprint);
            $partialBaseline[] = ['fingerprint' => $fingerprint];
        }

        (new Baseline())->save($baselineFile, $partialBaseline);

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
        ]);

        self::assertSame(2, substr_count($commandTester->getDisplay(), '[BASELINE-SKIPPED]'));
    }

    public function test_cli_baseline_option_overrides_the_configured_baseline_path(): void
    {
        $this->createProjectDir();
        $fullBaseline = $this->fixtureDir.'/full.json';
        $emptyBaseline = $this->fixtureDir.'/empty.json';

        $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}')->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $fullBaseline,
        ]);
        (new Baseline())->save($emptyBaseline, []);

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}', ['configuredBaseline' => $emptyBaseline]);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $fullBaseline,
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function test_configured_baseline_path_is_used_when_no_cli_option_is_given(): void
    {
        $this->createProjectDir();
        $baselineFile = $this->fixtureDir.'/configured.json';

        $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}')->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $baselineFile,
        ]);

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}', ['configuredBaseline' => $baselineFile]);
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertSame(5, substr_count($commandTester->getDisplay(), '[BASELINE-SKIPPED]'));
    }

    public function test_baseline_suppresses_matching_findings_and_clears_the_exit_code(): void
    {
        $this->createProjectDir();
        $baselineFile = $this->fixtureDir.'/baseline.json';

        $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}')->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $baselineFile,
        ]);

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertSame(5, substr_count($commandTester->getDisplay(), '[BASELINE-SKIPPED]'));
    }

    public function test_sarif_format_still_succeeds_when_the_pipeline_already_skipped_every_baselined_finding(): void
    {
        $this->createProjectDir();
        $baselineFile = $this->fixtureDir.'/baseline.json';

        $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}')->execute([
            'project-path' => $this->fixtureDir,
            '--generate-baseline' => $baselineFile,
        ]);

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--baseline' => $baselineFile,
            '--format' => 'sarif',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());

        $decoded = json_decode($commandTester->getDisplay(), true);
        self::assertIsArray($decoded);
        $runs = $decoded['runs'] ?? null;
        self::assertIsArray($runs);
        $firstRun = $runs[0] ?? null;
        self::assertIsArray($firstRun);

        self::assertSame([], $firstRun['results'] ?? null);
    }

    public function test_command_json_output_written_to_file(): void
    {
        $this->createProjectDir();
        $outputFile = $this->fixtureDir.'/report.json';

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
            '--output' => $outputFile,
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertFileExists($outputFile);
        $content = file_get_contents($outputFile);
        self::assertIsString($content);
        self::assertIsArray(json_decode($content, true));
    }

    public function test_command_exits_failure_for_critical_risk_level(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
    }

    public function test_command_shows_caution_message_for_critical_risk_level(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        $output = $commandTester->getDisplay();
        self::assertStringContainsString('CRITICAL', $output);
        self::assertStringContainsString('vulnerabilities found', $output);
    }

    public function test_command_shows_success_message_for_non_critical_project(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        $output = $commandTester->getDisplay();
        self::assertStringContainsString('Audit complete', $output);
        self::assertStringContainsString('Risk:', $output);
        self::assertStringContainsString('Vulnerabilities:', $output);
    }

    public function test_command_suppresses_success_message_for_machine_readable_json(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
        ]);

        $output = $commandTester->getDisplay();
        self::assertStringNotContainsString('Audit complete', $output);
        self::assertStringNotContainsString('Risk:', $output);
    }

    public function test_command_displays_title_and_pipeline_header(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        $output = $commandTester->getDisplay();
        self::assertStringContainsString('Symfony LLM Security Auditor', $output);
        self::assertStringContainsString('Pipeline:', $output);
    }

    public function test_command_displays_running_audit_pipeline_section(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringContainsString('Running audit pipeline', $commandTester->getDisplay());
    }

    public function test_command_exits_failure_and_shows_error_for_invalid_directory(): void
    {
        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => '/nonexistent/path/that/does/not/exist']);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
        self::assertStringContainsString('[ERROR]', $commandTester->getDisplay());
        self::assertStringContainsString('Project path', $commandTester->getDisplay());
    }

    public function test_command_defaults_project_path_to_cwd_when_argument_omitted(): void
    {
        $this->createProjectDir();
        $previousCwd = getcwd();
        self::assertNotFalse($previousCwd);
        chdir($this->fixtureDir);

        try {
            $commandTester = $this->makeCommandTester('[]', '{}');
            $commandTester->execute([]);

            self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
            self::assertStringContainsString('SAFE', $commandTester->getDisplay());
        } finally {
            chdir($previousCwd);
        }
    }

    public function test_command_header_contains_resolved_cwd_when_argument_omitted(): void
    {
        $this->createProjectDir();
        $previousCwd = getcwd();
        self::assertNotFalse($previousCwd);
        chdir($this->fixtureDir);

        try {
            $commandTester = $this->makeCommandTester('[]', '{}');
            $commandTester->execute([]);

            self::assertStringContainsString($this->fixtureDir, $commandTester->getDisplay());
        } finally {
            chdir($previousCwd);
        }
    }

    public function test_fail_on_default_critical_does_not_fail_high_risk_project(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->highAttackerPayload(), '{"accepted": true}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function test_cli_fail_on_high_fails_a_high_risk_project(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->highAttackerPayload(), '{"accepted": true}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--fail-on' => 'high',
        ]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
    }

    public function test_configured_fail_on_high_fails_a_high_risk_project_without_a_cli_option(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->highAttackerPayload(), '{"accepted": true}', ['riskLevel' => RiskLevel::High]);
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertSame(Command::FAILURE, $commandTester->getStatusCode());
    }

    public function test_cli_fail_on_overrides_a_stricter_configured_fail_on(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->highAttackerPayload(), '{"accepted": true}', ['riskLevel' => RiskLevel::High]);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--fail-on' => 'critical',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    public function test_excluded_type_is_dropped_from_report_and_clears_the_exit_code(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}', ['excludedTypes' => ['sql_injection']]);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        $output = $commandTester->getDisplay();
        preg_match('/(\{.*\})/s', $output, $matches);
        $decoded = json_decode($matches[1] ?? '', true);
        self::assertIsArray($decoded);
        self::assertSame(0, $decoded['total_vulnerabilities']);
    }

    public function test_included_types_allowlist_drops_unlisted_types(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}', ['includedTypes' => ['ssrf']]);
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
    }

    private function highAttackerPayload(): string
    {
        $vulns = [];
        for ($i = 1; $i <= 5; ++$i) {
            $vulns[] = [
                'type' => 'sql_injection',
                'severity' => 'high',
                'title' => \sprintf('High SQL Injection #%d', $i),
                'description' => 'Raw query with user input',
                'file_path' => \sprintf('src/Repo%d.php', $i),
                'line_start' => 1,
                'line_end' => 5,
                'vulnerable_code' => '$q',
                'attack_vector' => 'SQL injection via query param',
                'proof' => "' OR 1=1--",
                'remediation' => 'Use prepared statements',
                'confidence' => 0.95,
            ];
        }

        return (string) json_encode($vulns);
    }

    private function criticalAttackerPayload(): string
    {
        $vulns = [];
        for ($i = 1; $i <= 5; ++$i) {
            $vulns[] = [
                'type' => 'sql_injection',
                'severity' => 'critical',
                'title' => \sprintf('Critical SQL Injection #%d', $i),
                'description' => 'Raw query with user input',
                'file_path' => \sprintf('src/Repo%d.php', $i),
                'line_start' => 1,
                'line_end' => 5,
                'vulnerable_code' => '$q',
                'attack_vector' => 'SQL injection via query param',
                'proof' => "' OR 1=1--",
                'remediation' => 'Use prepared statements',
                'confidence' => 0.95,
            ];
        }

        return (string) json_encode($vulns);
    }

    #[Override]
    protected function setUp(): void
    {
        $this->fixtureDir = sys_get_temp_dir().'/cmd_e2e_'.uniqid('', true);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->rmdirRecursive($this->fixtureDir);
    }

    private function createProjectDir(): void
    {
        mkdir($this->fixtureDir.'/src/Controller', 0o777, true);
        file_put_contents(
            $this->fixtureDir.'/src/Controller/HomeController.php',
            '<?php class HomeController { public function index() {} }',
        );
    }

    /**
     * @param array{secretScrubbingEnabled?: bool, configuredBaseline?: string|null, riskLevel?: RiskLevel, excludedTypes?: list<string>, includedTypes?: list<string>, maxCostUsd?: float|null} $overrides
     */
    private function makeCommandTester(string $attackerResponse, string $reviewerResponse, array $overrides = []): CommandTester
    {
        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::of($attackerResponse, 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::of($reviewerResponse, 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        return $this->makeCommandTesterWithLLM($attackerLLM, $reviewerLLM, $overrides);
    }

    /**
     * @param array{secretScrubbingEnabled?: bool, configuredBaseline?: string|null, riskLevel?: RiskLevel, excludedTypes?: list<string>, includedTypes?: list<string>, maxCostUsd?: float|null} $overrides
     */
    private function makeCommandTesterWithLLM(LLMClientInterface $attackerLLM, LLMClientInterface $reviewerLLM, array $overrides = []): CommandTester
    {
        $secretScrubbingEnabled = $overrides['secretScrubbingEnabled'] ?? true;
        $configuredBaseline = $overrides['configuredBaseline'] ?? null;
        $riskLevel = $overrides['riskLevel'] ?? RiskLevel::Critical;
        $excludedTypes = $overrides['excludedTypes'] ?? [];
        $includedTypes = $overrides['includedTypes'] ?? [];
        $maxCostUsd = $overrides['maxCostUsd'] ?? null;

        $progressReporterHolder = new ProgressReporterHolder(new NullLogger());
        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent(
                new AttackerLlmCollaborators($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator())),
                new AttackerScanCollaborators(new NullAttackerCache(), progressReporter: $progressReporterHolder),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLLM,
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                    progressReporter: $progressReporterHolder,
                ),
                new ReviewerModeConfiguration(),
            ),
            new NullLogger(),
            new AuditLoopSettings(),
            progressReporter: $progressReporterHolder,
        );
        $auditPipeline = new AuditPipeline(
            [
                new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger()),
                new MappingStage(new NullLogger()),
                new AuditStage($auditOrchestrator, new NullLogger()),
            ],
            new NullLogger(),
            $progressReporterHolder,
        );

        $projectFileScanner = new ProjectFileScanner(new NullLogger());
        $estimateAuditCostUseCase = new EstimateAuditCostUseCase(
            $projectFileScanner,
            new ResolvingTokenEstimator(),
            new CostCalculator(new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/Fixture/pricing-catalog.json')),
            new NullLogger(),
            'stub',
            1,
        );
        $auditCommand = new AuditCommand(
            new RunAuditUseCase($auditPipeline, new NullLogger()),
            new ReportWriter([
                new ConsoleReportRenderer(),
                new JsonReportRenderer(),
                new SarifReportRenderer(),
                new HtmlReportRenderer(),
                new MarkdownReportRenderer(),
                new JunitReportRenderer(),
            ], new Filesystem()),
            new AuditExitCodeResolver(),
            new AuditPresenter(new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/Fixture/pricing-catalog.json')),
            $estimateAuditCostUseCase,
            new ListScannedFilesUseCase($projectFileScanner),
            $progressReporterHolder,
            new BaselineProcessor(new Baseline(), $configuredBaseline),
            new UnpricedModelBudgetGuard(
                new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/Fixture/pricing-catalog.json'),
                ['stub'],
                $maxCostUsd,
            ),
            secretScrubbingEnabled: $secretScrubbingEnabled,
            findingTypeFilter: new FindingTypeFilter($includedTypes, $excludedTypes),
            riskLevel: $riskLevel,
        );

        return new CommandTester($auditCommand);
    }

    public function test_command_exits_with_budget_exit_code_when_audit_is_aborted_by_budget(): void
    {
        $this->createProjectDir();

        $abortingAttacker = self::createStub(LLMClientInterface::class);
        $abortingAttacker->method('complete')->willThrowException(
            BudgetExceededException::forCost(1.5, 1.0),
        );
        $abortingAttacker->method('completeWithTools')->willThrowException(
            BudgetExceededException::forCost(1.5, 1.0),
        );
        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(LLMResponse::of('{}', 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $commandTester = $this->makeCommandTesterWithLLM($abortingAttacker, $reviewerLLM);
        $outputFile = $this->fixtureDir.'/partial.json';
        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
            '--output' => $outputFile,
        ]);

        self::assertSame(2, $exitCode);
        self::assertFileExists($outputFile);
        $decoded = json_decode((string) file_get_contents($outputFile), true);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('audit_id', $decoded);
    }

    public function test_dry_run_with_console_format_shows_success_message(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--dry-run' => true,
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringContainsString('Estimating audit cost', $commandTester->getDisplay());
        self::assertStringContainsString('Dry run complete', $commandTester->getDisplay());
        self::assertStringContainsString('Dry run', $commandTester->getDisplay());
        self::assertStringNotContainsString('Audit complete', $commandTester->getDisplay());
        self::assertStringNotContainsString('RISK LEVEL', $commandTester->getDisplay());
    }

    public function test_dry_run_warns_when_configured_model_is_unsupported(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--dry-run' => true,
        ]);

        self::assertStringContainsString('No published pricing', $commandTester->getDisplay());
    }

    public function test_dry_run_model_warning_is_emitted_on_stderr_for_machine_readable_output(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(
            [
                'project-path' => $this->fixtureDir,
                '--dry-run' => true,
                '--format' => 'json',
            ],
            ['capture_stderr_separately' => true],
        );

        self::assertStringContainsString('No published pricing', $commandTester->getErrorOutput());
        self::assertStringNotContainsString('No published pricing', $commandTester->getDisplay());
    }

    public function test_command_renders_progress_bar_in_decorated_console_output(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir], ['decorated' => true]);

        self::assertStringContainsString('3/3', $commandTester->getDisplay());
    }

    public function test_command_renders_plain_progress_without_a_bar_in_non_decorated_output(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir], ['decorated' => false]);

        self::assertStringNotContainsString('3/3', $commandTester->getDisplay());
    }

    public function test_command_streams_findings_in_non_decorated_output(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester($this->criticalAttackerPayload(), '{"accepted": true}');
        $commandTester->execute(['project-path' => $this->fixtureDir], ['decorated' => false]);

        self::assertStringContainsString('[CRITICAL] sql_injection', $commandTester->getDisplay());
    }

    public function test_command_suppresses_progress_bar_in_machine_readable_stdout(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
        ]);

        self::assertStringNotContainsString('3/3', $commandTester->getDisplay());
    }

    public function test_command_shows_audit_iteration_progress_in_decorated_console_output(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir], ['decorated' => true]);

        self::assertStringContainsString('audit · iteration 1/3', $commandTester->getDisplay());
    }

    public function test_command_shows_audit_iteration_progress_in_non_decorated_output(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir], ['decorated' => false]);

        self::assertStringContainsString('Iteration 1/3', $commandTester->getDisplay());
    }

    public function test_command_shows_long_run_notice_in_console_format(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringContainsString('20+ minutes', $commandTester->getDisplay());
    }

    public function test_command_suppresses_long_run_notice_in_machine_readable_stdout(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
        ]);

        self::assertStringNotContainsString('20+ minutes', $commandTester->getDisplay());
    }

    public function test_dry_run_with_machine_readable_json_format_suppresses_success_message(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--dry-run' => true,
            '--format' => 'json',
        ]);

        self::assertSame(Command::SUCCESS, $commandTester->getStatusCode());
        self::assertStringNotContainsString('Audit complete', $commandTester->getDisplay());
        self::assertStringNotContainsString('Risk:', $commandTester->getDisplay());
    }

    public function test_budget_aborted_command_renders_error_message_to_display(): void
    {
        $this->createProjectDir();

        $abortingAttacker = self::createStub(LLMClientInterface::class);
        $abortingAttacker->method('complete')->willThrowException(
            BudgetExceededException::forCost(1.5, 1.0),
        );
        $abortingAttacker->method('completeWithTools')->willThrowException(
            BudgetExceededException::forCost(1.5, 1.0),
        );
        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(LLMResponse::of('{}', 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $commandTester = $this->makeCommandTesterWithLLM($abortingAttacker, $reviewerLLM);
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringContainsString('[ERROR]', $commandTester->getDisplay());
    }

    public function test_dry_run_emits_estimated_cost_without_invoking_llm(): void
    {
        $this->createProjectDir();
        mkdir($this->fixtureDir.'/src/Controller', 0o777, true);
        file_put_contents($this->fixtureDir.'/src/Controller/UserController.php', '<?php class UserController { public function indexAction() {} }');

        $throwingLLM = new class implements LLMClientInterface {
            #[Override]
            public function complete(string $systemPrompt, string $userMessage): LLMResponse
            {
                throw new RuntimeException('platform must not be invoked during --dry-run');
            }

            #[Override]
            public function completeWithTools(
                string $systemPrompt,
                string $userMessage,
                ToolRegistry $toolRegistry,
                int $maxToolIterations,
            ): LLMResponse {
                throw new RuntimeException('platform must not be invoked during --dry-run');
            }

            #[Override]
            public function model(): string
            {
                return 'stub';
            }
        };

        $commandTester = $this->makeCommandTesterWithLLM($throwingLLM, $throwingLLM);

        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--dry-run' => true,
            '--format' => 'json',
            '--output' => $this->fixtureDir.'/report.json',
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $reportPath = $this->fixtureDir.'/report.json';
        self::assertFileExists($reportPath);
        $decoded = json_decode((string) file_get_contents($reportPath), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('cost', $decoded);
        $cost = $decoded['cost'];
        self::assertIsArray($cost);
        self::assertGreaterThan(0, $cost['input_tokens']);
        self::assertGreaterThan(0, $cost['output_tokens']);
        self::assertSame('stub', $cost['primary_model']);
    }

    public function test_show_scanned_lists_files_and_exits_success_without_invoking_llm(): void
    {
        $this->createProjectDir();

        $llmClient = $this->throwingLLMClient();
        $commandTester = $this->makeCommandTesterWithLLM($llmClient, $llmClient);
        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--show-scanned' => true,
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $display = $commandTester->getDisplay();
        self::assertStringContainsString('Scanned files', $display);
        self::assertStringContainsString('HomeController.php', $display);
        self::assertStringContainsString('file(s) in scope', $display);
        self::assertStringNotContainsString('Running audit pipeline', $display);
    }

    public function test_show_scanned_honors_the_path_filter(): void
    {
        $this->createProjectDir();

        $llmClient = $this->throwingLLMClient();
        $commandTester = $this->makeCommandTesterWithLLM($llmClient, $llmClient);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--show-scanned' => true,
            '--path' => ['nonexistent'],
        ]);

        self::assertStringContainsString('No files matched', $commandTester->getDisplay());
    }

    public function test_show_scanned_with_dry_run_lists_files_before_the_cost_estimate(): void
    {
        $this->createProjectDir();

        $llmClient = $this->throwingLLMClient();
        $commandTester = $this->makeCommandTesterWithLLM($llmClient, $llmClient);
        $exitCode = $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--show-scanned' => true,
            '--dry-run' => true,
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $display = $commandTester->getDisplay();
        $scannedPosition = mb_strpos($display, 'file(s) in scope');
        $dryRunPosition = mb_strpos($display, 'Dry run complete');
        self::assertIsInt($scannedPosition);
        self::assertIsInt($dryRunPosition);
        self::assertLessThan($dryRunPosition, $scannedPosition);
    }

    public function test_show_scanned_with_dry_run_omits_the_show_scanned_tip(): void
    {
        $this->createProjectDir();

        $llmClient = $this->throwingLLMClient();
        $commandTester = $this->makeCommandTesterWithLLM($llmClient, $llmClient);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--show-scanned' => true,
            '--dry-run' => true,
        ]);

        self::assertStringNotContainsString('Tip: run with --show-scanned', $commandTester->getDisplay());
    }

    public function test_dry_run_alone_emits_the_show_scanned_tip(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--dry-run' => true,
        ]);

        self::assertStringContainsString('Tip: run with --show-scanned', $commandTester->getDisplay());
    }

    private function throwingLLMClient(): LLMClientInterface
    {
        return new class implements LLMClientInterface {
            #[Override]
            public function complete(string $systemPrompt, string $userMessage): LLMResponse
            {
                throw new RuntimeException('the LLM platform must not be invoked for --show-scanned');
            }

            #[Override]
            public function completeWithTools(
                string $systemPrompt,
                string $userMessage,
                ToolRegistry $toolRegistry,
                int $maxToolIterations,
            ): LLMResponse {
                throw new RuntimeException('the LLM platform must not be invoked for --show-scanned');
            }

            #[Override]
            public function model(): string
            {
                return 'stub';
            }
        };
    }

    private function rmdirRecursive(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $items = scandir($dir);
        if (false === $items) {
            return;
        }

        foreach ($items as $item) {
            if ('.' === $item) {
                continue;
            }

            if ('..' === $item) {
                continue;
            }

            $path = $dir.'/'.$item;
            is_dir($path) ? $this->rmdirRecursive($path) : unlink($path);
        }

        rmdir($dir);
    }
}
