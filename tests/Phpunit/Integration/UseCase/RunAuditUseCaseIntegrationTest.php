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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\UseCase;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

final class RunAuditUseCaseIntegrationTest extends TestCase
{
    private string $tmpDir;

    public function test_execute_returns_audit_report_instance(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Service.php', '<?php class Service {}');

        $auditReport = $this->makeUseCase('[]', '{}')->execute($this->tmpDir);

        self::assertInstanceOf(AuditReport::class, $auditReport);
    }

    public function test_execute_report_contains_correct_project_path(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Service.php', '<?php class Service {}');

        $auditReport = $this->makeUseCase('[]', '{}')->execute($this->tmpDir);

        self::assertSame($this->tmpDir, $auditReport->projectPath());
    }

    public function test_execute_report_files_scanned_matches_real_file_count(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        mkdir($this->tmpDir.'/src/Entity', 0o777, true);

        file_put_contents($this->tmpDir.'/src/Controller/UserController.php', '<?php');
        file_put_contents($this->tmpDir.'/src/Entity/User.php', '<?php');

        $auditReport = $this->makeUseCase('[]', '{}')->execute($this->tmpDir);

        self::assertSame(2, $auditReport->filesScanned());
    }

    public function test_execute_returns_safe_report_when_no_vulnerabilities_found(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Service.php', '<?php class Service {}');

        $auditReport = $this->makeUseCase('[]', '{}')->execute($this->tmpDir);

        self::assertSame('SAFE', $auditReport->riskLevel());
        self::assertSame(0, $auditReport->totalVulnerabilities());
    }

    public function test_execute_report_contains_vulnerability_found_by_stub_llm(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/src/Controller/AdminController.php',
            '<?php class AdminController { public function dashboard() {} }',
        );

        $vulnJson = $this->makeVulnerabilityJson('src/Controller/AdminController.php');
        $reviewJson = (string) json_encode(['accepted' => true, 'adjusted_severity' => null, 'reviewer_notes' => 'Confirmed']);

        $auditReport = $this->makeUseCase($vulnJson, $reviewJson)->execute($this->tmpDir);

        self::assertSame(1, $auditReport->totalVulnerabilities());
        self::assertSame('Missing access control on admin route', $auditReport->vulnerabilities()[0]->title());
    }

    public function test_execute_report_audit_id_is_non_empty(): void
    {
        mkdir($this->tmpDir.'/src', 0o777, true);
        file_put_contents($this->tmpDir.'/src/App.php', '<?php');

        $auditReport = $this->makeUseCase('[]', '{}')->execute($this->tmpDir);

        self::assertNotEmpty($auditReport->auditId());
        self::assertStringStartsWith('AUDIT-', $auditReport->auditId());
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/usecase_int_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        $this->rmdirRecursive($this->tmpDir);
    }

    private function makeUseCase(string $attackerResponse, string $reviewerResponse): RunAuditUseCase
    {
        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::create($attackerResponse, 0, 0, 'stub', 'end_turn'),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::create($reviewerResponse, 0, 0, 'stub', 'end_turn'),
        );

        return $this->makeUseCaseWithLLM($attackerLLM, $reviewerLLM);
    }

    private function makeUseCaseWithLLM(LLMClientInterface $attackerLLM, LLMClientInterface $reviewerLLM): RunAuditUseCase
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

        return new RunAuditUseCase($auditPipeline, new NullLogger());
    }

    private function makeVulnerabilityJson(string $filePath): string
    {
        return (string) json_encode([[
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => 'Missing access control on admin route',
            'description' => 'No security check on the admin route',
            'file_path' => $filePath,
            'line_start' => 10,
            'line_end' => 20,
            'vulnerable_code' => 'public function dashboard()',
            'attack_vector' => 'Direct URL access',
            'proof' => 'GET /admin/dashboard',
            'remediation' => 'Add #[IsGranted("ROLE_ADMIN")]',
            'confidence' => 0.9,
        ]]);
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
