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

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\EstimateAuditCostUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CharacterBasedTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\StaticPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ProgressReporterHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditExitCodeResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditPresenter;
use VinceAmstoutz\SymfonySecurityAuditor\Command\ReportWriter;

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

    public function test_command_emits_secret_scrubbing_warning_when_scrubbing_disabled(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}', secretScrubbingEnabled: false);
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringContainsString('Secret scrubbing is disabled', $commandTester->getDisplay());
    }

    public function test_command_is_silent_about_scrubbing_when_enabled(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}', secretScrubbingEnabled: true);
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringNotContainsString('Secret scrubbing is disabled', $commandTester->getDisplay());
    }

    public function test_command_suppresses_scrubbing_warning_when_output_is_machine_readable(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}', secretScrubbingEnabled: false);
        $commandTester->execute([
            'project-path' => $this->fixtureDir,
            '--format' => 'json',
        ]);

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

    protected function setUp(): void
    {
        $this->fixtureDir = sys_get_temp_dir().'/cmd_e2e_'.uniqid('', true);
    }

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

    private function makeCommandTester(string $attackerResponse, string $reviewerResponse, bool $secretScrubbingEnabled = true): CommandTester
    {
        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::create($attackerResponse, 0, 0, 'stub', 'end_turn'),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::create($reviewerResponse, 0, 0, 'stub', 'end_turn'),
        );

        return $this->makeCommandTesterWithLLM($attackerLLM, $reviewerLLM, $secretScrubbingEnabled);
    }

    private function makeCommandTesterWithLLM(LLMClientInterface $attackerLLM, LLMClientInterface $reviewerLLM, bool $secretScrubbingEnabled = true): CommandTester
    {
        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator()), new NullAttackerCache(), new NullLogger()),
            new ReviewerAgent($reviewerLLM, new ReviewerPromptBuilder(), new NullLogger()),
            new NullLogger(),
        );

        $progressReporterHolder = new ProgressReporterHolder();
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
            new CharacterBasedTokenEstimator(),
            new CostCalculator(new StaticPricingProvider(new NullLogger())),
            new NullLogger(),
            'stub',
            1,
        );
        $auditCommand = new AuditCommand(
            new RunAuditUseCase($auditPipeline, new NullLogger()),
            new ReportWriter(new ReportRenderer(), new Filesystem()),
            new AuditExitCodeResolver(),
            new AuditPresenter(),
            $estimateAuditCostUseCase,
            $progressReporterHolder,
            secretScrubbingEnabled: $secretScrubbingEnabled,
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
        $reviewerLLM->method('complete')->willReturn(LLMResponse::create('{}', 0, 0, 'stub', 'end_turn'));

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

    public function test_command_renders_progress_bar_in_console_format(): void
    {
        $this->createProjectDir();

        $commandTester = $this->makeCommandTester('[]', '{}');
        $commandTester->execute(['project-path' => $this->fixtureDir]);

        self::assertStringContainsString('3/3', $commandTester->getDisplay());
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
        $reviewerLLM->method('complete')->willReturn(LLMResponse::create('{}', 0, 0, 'stub', 'end_turn'));

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
            public function complete(string $systemPrompt, string $userMessage): LLMResponse
            {
                throw new RuntimeException('platform must not be invoked during --dry-run');
            }

            public function completeWithTools(
                string $systemPrompt,
                string $userMessage,
                ToolRegistry $toolRegistry,
                int $maxToolIterations,
            ): LLMResponse {
                throw new RuntimeException('platform must not be invoked during --dry-run');
            }

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

    private function rmdirRecursive(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (scandir($dir) as $item) {
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
