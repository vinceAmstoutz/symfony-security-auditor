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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Pipeline;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\AuditPipeline;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullSecurityConfigParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

final class AuditPipelineIntegrationTest extends TestCase
{
    private string $tmpDir;

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidTokenUsageException
     */
    public function test_ingestion_stage_scans_real_filesystem(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/src/Controller/AdminController.php',
            '<?php class AdminController { public function index() {} }',
        );

        $auditPipeline = $this->makePipeline('[]', '{}');
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        self::assertCount(1, $auditContext->projectFiles());
        self::assertSame('src/Controller/AdminController.php', $auditContext->projectFiles()[0]->relativePath());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidTokenUsageException
     */
    public function test_mapping_stage_classifies_scanned_files(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        mkdir($this->tmpDir.'/src/Entity', 0o777, true);
        mkdir($this->tmpDir.'/src/Security', 0o777, true);

        file_put_contents($this->tmpDir.'/src/Controller/UserController.php', '<?php class UserController {}');
        file_put_contents($this->tmpDir.'/src/Entity/User.php', '<?php class User {}');
        file_put_contents($this->tmpDir.'/src/Security/UserVoter.php', '<?php class UserVoter {}');

        $auditPipeline = $this->makePipeline('[]', '{}');
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        self::assertNotNull($auditContext->mapping());
        self::assertSame(1, $auditContext->getMeta('mapping.controllers'));
        self::assertSame(1, $auditContext->getMeta('mapping.entities'));
        self::assertSame(1, $auditContext->getMeta('mapping.voters'));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidTokenUsageException
     */
    public function test_full_pipeline_produces_validated_vulnerability_from_stub_llm(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/src/Controller/AdminController.php',
            '<?php class AdminController { public function dashboard() {} }',
        );

        $auditPipeline = $this->makePipeline(
            attackerResponse: $this->makeVulnerabilityJson('src/Controller/AdminController.php'),
            reviewerResponse: (string) json_encode(['accepted' => true, 'adjusted_severity' => null, 'reviewer_notes' => 'Confirmed']),
        );

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        self::assertCount(1, $auditContext->validatedVulnerabilities());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidTokenUsageException
     */
    public function test_full_pipeline_stores_no_vulnerabilities_when_attacker_finds_nothing(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents(
            $this->tmpDir.'/src/Controller/SecureController.php',
            '<?php #[IsGranted("ROLE_ADMIN")] class SecureController {}',
        );

        $auditPipeline = $this->makePipeline('[]', '{}');
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        self::assertEmpty($auditContext->validatedVulnerabilities());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidTokenUsageException
     */
    public function test_pipeline_stores_audit_metadata_after_run(): void
    {
        mkdir($this->tmpDir.'/src/Controller', 0o777, true);
        file_put_contents($this->tmpDir.'/src/Controller/FooController.php', '<?php class FooController {}');

        $auditPipeline = $this->makePipeline('[]', '{}');
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditPipeline->process($auditContext);

        self::assertSame(1, $auditContext->getMeta('ingestion.file_count'));
        self::assertSame(1, $auditContext->getMeta('mapping.controllers'));
        self::assertNotNull($auditContext->getMeta('audit.iterations'));
        self::assertNotNull($auditContext->getMeta('audit.risk_score'));
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/pipeline_int_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->rmdirRecursive($this->tmpDir);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function makePipeline(string $attackerResponse, string $reviewerResponse): AuditPipeline
    {
        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::of($attackerResponse, 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::of($reviewerResponse, 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent(
                new AttackerLlmCollaborators($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator()), new NullCodeSlicer()),
                new AttackerScanCollaborators(new NullAttackerCache(), new NullStaticPreScanner(), new NullProgressReporter()),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLLM,
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                ),
                new ReviewerModeConfiguration(),
            ),
            new NullLogger(),
            new AuditLoopSettings(),
            progressReporter: new NullProgressReporter(),
        );

        return new AuditPipeline(
            [
                new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger()),
                new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser()),
                new AuditStage($auditOrchestrator, new NullLogger()),
            ],
            new NullLogger(),
            new NullProgressReporter(),
        );
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
