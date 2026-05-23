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
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
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

    private function makeCommandTester(string $attackerResponse, string $reviewerResponse): CommandTester
    {
        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::create($attackerResponse, 0, 0, 'stub', 'end_turn'),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::create($reviewerResponse, 0, 0, 'stub', 'end_turn'),
        );

        return $this->makeCommandTesterWithLLM($attackerLLM, $reviewerLLM);
    }

    private function makeCommandTesterWithLLM(LLMClientInterface $attackerLLM, LLMClientInterface $reviewerLLM): CommandTester
    {
        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger()), new NullAttackerCache(), new NullLogger()),
            new ReviewerAgent($reviewerLLM, new ReviewerPromptBuilder(), new NullLogger()),
            new NullLogger(),
        );

        $auditPipeline = new AuditPipeline(
            [
                new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger()),
                new MappingStage(new NullLogger()),
                new AuditStage($auditOrchestrator, new NullLogger()),
            ],
            new NullLogger(),
        );

        $auditCommand = new AuditCommand(
            new RunAuditUseCase($auditPipeline, new NullLogger()),
            new ReportWriter(new ReportRenderer(), new Filesystem()),
            new AuditExitCodeResolver(),
            new AuditPresenter(),
        );

        return new CommandTester($auditCommand);
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
