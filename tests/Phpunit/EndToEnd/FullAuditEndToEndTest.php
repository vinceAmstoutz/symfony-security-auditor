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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

/**
 * End-to-end tests exercise the full audit workflow against a realistic Symfony project fixture.
 *
 * The LLM boundary is replaced with deterministic fixture responses so tests are
 * fast, reproducible, and require no API credentials.
 */
final class FullAuditEndToEndTest extends TestCase
{
    private string $fixtureProjectDir;

    public function test_audit_of_unprotected_symfony_project_produces_critical_report(): void
    {
        $this->createSymfonyProjectFixture(secure: false);

        $attackerResponses = [
            $this->makeVulnerabilityJson('src/Controller/AdminController.php', 'critical', 'Missing ROLE_ADMIN check', 0.95),
            $this->makeVulnerabilityJson('src/Controller/ApiController.php', 'high', 'No authentication on API endpoint', 0.9),
        ];
        $callIndex = 0;
        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturnCallback(
            static function () use ($attackerResponses, &$callIndex): LLMResponse {
                $response = $attackerResponses[$callIndex] ?? '[]';
                ++$callIndex;

                return LLMResponse::of($response, 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0));
            },
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::of((string) json_encode(['accepted' => true, 'adjusted_severity' => null, 'reviewer_notes' => 'Confirmed']), 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $auditReport = $this->makeUseCase($attackerLLM, $reviewerLLM)->execute($this->fixtureProjectDir);

        self::assertGreaterThanOrEqual(1, $auditReport->totalVulnerabilities());
        self::assertContains($auditReport->riskLevel(), ['HIGH', 'CRITICAL', 'MEDIUM']);
        self::assertGreaterThan(0, $auditReport->riskScore());
    }

    public function test_audit_of_secured_project_produces_safe_report(): void
    {
        $this->createSymfonyProjectFixture(secure: true);

        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::of('[]', 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);

        $auditReport = $this->makeUseCase($attackerLLM, $reviewerLLM)->execute($this->fixtureProjectDir);

        self::assertSame(0, $auditReport->totalVulnerabilities());
        self::assertSame('SAFE', $auditReport->riskLevel());
        self::assertSame(0, $auditReport->riskScore());
    }

    public function test_audit_report_vulnerability_has_correct_owasp_type(): void
    {
        $this->createSymfonyProjectFixture(secure: false);

        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::of($this->makeVulnerabilityJson('src/Controller/AdminController.php', 'high', 'SQL injection', 0.9, 'sql_injection'), 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::of((string) json_encode(['accepted' => true, 'adjusted_severity' => null]), 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $auditReport = $this->makeUseCase($attackerLLM, $reviewerLLM)->execute($this->fixtureProjectDir);

        self::assertCount(1, $auditReport->vulnerabilitiesByType(VulnerabilityType::SQL_INJECTION));
    }

    public function test_audit_report_serialises_to_valid_json(): void
    {
        $this->createSymfonyProjectFixture(secure: false);

        $attackerLLM = self::createStub(LLMClientInterface::class);
        $attackerLLM->method('complete')->willReturn(
            LLMResponse::of($this->makeVulnerabilityJson('src/Controller/AdminController.php', 'high', 'Missing check', 0.9), 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $reviewerLLM = self::createStub(LLMClientInterface::class);
        $reviewerLLM->method('complete')->willReturn(
            LLMResponse::of((string) json_encode(['accepted' => true]), 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)),
        );

        $auditReport = $this->makeUseCase($attackerLLM, $reviewerLLM)->execute($this->fixtureProjectDir);

        $data = $auditReport->toArray();

        self::assertArrayHasKey('audit_id', $data);
        self::assertArrayHasKey('risk_level', $data);
        self::assertArrayHasKey('vulnerabilities', $data);
        self::assertArrayHasKey('files_scanned', $data);
        self::assertIsString(json_encode($data));
    }

    protected function setUp(): void
    {
        $this->fixtureProjectDir = sys_get_temp_dir().'/e2e_project_'.uniqid('', true);
        mkdir($this->fixtureProjectDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        $this->rmdirRecursive($this->fixtureProjectDir);
    }

    private function createSymfonyProjectFixture(bool $secure): void
    {
        $dirs = [
            'src/Controller',
            'src/Entity',
            'src/Security',
            'src/Repository',
            'config',
            'templates',
        ];

        foreach ($dirs as $dir) {
            mkdir($this->fixtureProjectDir.'/'.$dir, 0o777, true);
        }

        $securityAttr = $secure ? '#[IsGranted("ROLE_ADMIN")]' : '';

        file_put_contents(
            $this->fixtureProjectDir.'/src/Controller/AdminController.php',
            \sprintf('<?php %s class AdminController { public function dashboard() {} public function users() {} }', $securityAttr),
        );

        file_put_contents(
            $this->fixtureProjectDir.'/src/Controller/ApiController.php',
            \sprintf('<?php %s class ApiController { public function list() {} }', $securityAttr),
        );

        file_put_contents(
            $this->fixtureProjectDir.'/src/Entity/User.php',
            '<?php class User { private string $email; private string $password; }',
        );

        file_put_contents(
            $this->fixtureProjectDir.'/src/Security/UserVoter.php',
            '<?php class UserVoter extends Voter {}',
        );

        file_put_contents(
            $this->fixtureProjectDir.'/src/Repository/UserRepository.php',
            '<?php class UserRepository { public function findByEmail(string $email) {} }',
        );

        $securityConfig = $secure
            ? "security:\n  access_control:\n    - path: ^/admin\n      roles: ROLE_ADMIN\n"
            : "security:\n  firewalls:\n    main:\n      pattern: ^/\n";

        file_put_contents(
            $this->fixtureProjectDir.'/config/security.yaml',
            $securityConfig,
        );

        file_put_contents(
            $this->fixtureProjectDir.'/templates/base.html.twig',
            '<!DOCTYPE html><html><body>{% block body %}{% endblock %}</body></html>',
        );
    }

    private function makeUseCase(LLMClientInterface $attackerLLM, LLMClientInterface $reviewerLLM): RunAuditUseCase
    {
        $auditOrchestrator = new AuditOrchestrator(
            new AttackerAgent(new AttackerLlmCollaborators($attackerLLM, new AttackerPromptBuilder(), new VulnerabilityFactory(new NullLogger(), Validation::createValidator())), new AttackerScanCollaborators(new NullAttackerCache()), new AttackerAnalysisSettings(), new NullLogger()),
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

    private function makeVulnerabilityJson(
        string $filePath,
        string $severity = 'high',
        string $title = 'Missing access control',
        float $confidence = 0.9,
        string $type = 'broken_access_control',
    ): string {
        return (string) json_encode([[
            'type' => $type,
            'severity' => $severity,
            'title' => $title,
            'description' => 'Security vulnerability detected',
            'file_path' => $filePath,
            'line_start' => 10,
            'line_end' => 20,
            'vulnerable_code' => 'public function index()',
            'attack_vector' => 'Direct URL access',
            'proof' => 'GET /admin',
            'remediation' => 'Add access control',
            'confidence' => $confidence,
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
