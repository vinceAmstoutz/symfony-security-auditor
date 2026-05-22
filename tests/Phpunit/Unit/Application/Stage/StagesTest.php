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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Stage;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestrator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\ReviewerAgent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

final class StagesTest extends TestCase
{
    private string $tmpDir;

    public function test_ingestion_stage_has_correct_name(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $ingestionStage = new IngestionStage($scanner, new NullLogger());

        self::assertSame('ingestion', $ingestionStage->name());
    }

    public function test_ingestion_stage_populates_context_with_scanned_files(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $files = [
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
            ProjectFile::create('src/B.php', '/app/src/B.php', '<?php'),
        ];

        $scanner->method('scan')->willReturn($files);

        $ingestionStage = new IngestionStage($scanner, new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $ingestionStage->process($auditContext);

        self::assertCount(2, $auditContext->projectFiles());
        self::assertSame(2, $auditContext->getMeta('ingestion.file_count'));
    }

    public function test_ingestion_stage_handles_empty_scan_result(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $scanner->method('scan')->willReturn([]);

        $ingestionStage = new IngestionStage($scanner, new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $ingestionStage->process($auditContext);

        self::assertCount(0, $auditContext->projectFiles());
        self::assertSame(0, $auditContext->getMeta('ingestion.file_count'));
    }

    public function test_mapping_stage_has_correct_name(): void
    {
        $mappingStage = new MappingStage(new NullLogger());

        self::assertSame('mapping', $mappingStage->name());
    }

    public function test_mapping_stage_creates_mapping_from_project_files(): void
    {
        $mappingStage = new MappingStage(new NullLogger());

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', '<?php class UserController {}'),
            ProjectFile::create('src/Entity/User.php', '/app/src/Entity/User.php', '<?php class User {}'),
            ProjectFile::create('src/Security/UserVoter.php', '/app/src/Security/UserVoter.php', '<?php class UserVoter {}'),
            ProjectFile::create('src/Repository/UserRepository.php', '/app/src/Repository/UserRepository.php', '<?php class UserRepository {}'),
            ProjectFile::create('src/Form/UserType.php', '/app/src/Form/UserType.php', '<?php class UserType {}'),
            ProjectFile::create('templates/user.html.twig', '/app/templates/user.html.twig', '{{ user.name }}'),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertCount(1, $mapping->controllers());
        self::assertCount(1, $mapping->entities());
        self::assertCount(1, $mapping->voters());
        self::assertCount(1, $mapping->repositories());
        self::assertCount(1, $mapping->forms());
        self::assertCount(1, $mapping->templates());
    }

    public function test_mapping_stage_handles_empty_file_list(): void
    {
        $mappingStage = new MappingStage(new NullLogger());

        $auditContext = AuditContext::forProject($this->tmpDir);
        // No files set

        $mappingStage->process($auditContext);

        self::assertNotNull($auditContext->mapping());
        self::assertSame(0, $auditContext->mapping()->totalFiles());
    }

    public function test_mapping_stage_extracts_security_config(): void
    {
        $mappingStage = new MappingStage(new NullLogger());

        $securityYaml = <<<'YAML'
            security:
                firewalls:
                    main:
                        pattern: ^/
                access_control:
                    - path: ^/admin
                      roles: ROLE_ADMIN
            YAML;

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('config/security.yaml', '/app/config/security.yaml', $securityYaml),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertNotEmpty($mapping->firewallRules());
    }

    public function test_audit_stage_has_correct_name(): void
    {
        $auditStage = new AuditStage($this->makeOrchestrator(), new NullLogger());

        self::assertSame('audit', $auditStage->name());
    }

    public function test_audit_stage_skips_when_no_files(): void
    {
        $attackerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $attackerLlm->expects(self::never())->method('complete');
        $reviewerLlm->expects(self::never())->method('complete');

        $auditStage = new AuditStage($this->makeOrchestrator($attackerLlm, $reviewerLlm), new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);
        // No files, no mapping

        $auditStage->process($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
        self::assertNull($auditContext->getMeta('audit.iterations'));
    }

    public function test_audit_stage_skips_when_no_mapping(): void
    {
        $attackerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm = $this->createMock(LLMClientInterface::class);
        $attackerLlm->expects(self::never())->method('complete');
        $reviewerLlm->expects(self::never())->method('complete');

        $auditStage = new AuditStage($this->makeOrchestrator($attackerLlm, $reviewerLlm), new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
        ]);
        // Mapping NOT set

        $auditStage->process($auditContext);

        self::assertEmpty($auditContext->vulnerabilities());
        self::assertNull($auditContext->getMeta('audit.iterations'));
    }

    public function test_audit_stage_calls_orchestrator_when_ready(): void
    {
        $attackerLlm = $this->createMock(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(LLMResponse::create('[]', 0, 0, 'stub', 'end_turn'));

        $auditStage = new AuditStage($this->makeOrchestrator($attackerLlm, $reviewerLlm), new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
        ]);
        $auditContext->setMapping(SymfonyMapping::create());

        $auditStage->process($auditContext);

        // Orchestrator ran (writes the audit.iterations meta) and finished cleanly.
        self::assertNotNull($auditContext->getMeta('audit.iterations'));
    }

    public function test_ingestion_stage_sets_total_lines_meta(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $files = [
            ProjectFile::create('src/A.php', '/app/src/A.php', "<?php\nclass A {}"),
            ProjectFile::create('src/B.php', '/app/src/B.php', "<?php\nclass B {}\n// end"),
        ];
        $scanner->method('scan')->willReturn($files);

        $ingestionStage = new IngestionStage($scanner, new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $ingestionStage->process($auditContext);

        self::assertSame(5, $auditContext->getMeta('ingestion.total_lines'));
    }

    public function test_mapping_stage_sets_meta_counts(): void
    {
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', '<?php class UserController {}'),
            ProjectFile::create('src/Controller/AdminController.php', '/app/src/Controller/AdminController.php', '<?php #[IsGranted("ROLE_ADMIN")] class AdminController {}'),
            ProjectFile::create('src/Entity/User.php', '/app/src/Entity/User.php', '<?php class User {}'),
            ProjectFile::create('src/Security/UserVoter.php', '/app/src/Security/UserVoter.php', '<?php class UserVoter {}'),
        ]);

        $mappingStage->process($auditContext);

        self::assertSame(2, $auditContext->getMeta('mapping.controllers'));
        self::assertSame(1, $auditContext->getMeta('mapping.entities'));
        self::assertSame(1, $auditContext->getMeta('mapping.voters'));
        self::assertSame(1, $auditContext->getMeta('mapping.no_voter_controllers'));
    }

    public function test_mapping_stage_sets_no_voter_controllers_to_zero_when_all_secured(): void
    {
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create(
                'src/Controller/SecureController.php',
                '/app/src/Controller/SecureController.php',
                '<?php #[IsGranted("ROLE_ADMIN")] class SecureController {}',
            ),
        ]);

        $mappingStage->process($auditContext);

        self::assertSame(0, $auditContext->getMeta('mapping.no_voter_controllers'));
    }

    public function test_mapping_stage_processes_all_config_files_not_just_first(): void
    {
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $security1 = "security:\n    firewalls:\n        main:\n            pattern: ^/api\n";
        $security2 = "security:\n    firewalls:\n        admin:\n            pattern: ^/admin\n";

        $auditContext->setProjectFiles([
            ProjectFile::create('src/Controller/Foo.php', '/app/src/Controller/Foo.php', '<?php'),
            ProjectFile::create('config/security.yaml', '/app/config/security.yaml', $security1),
            ProjectFile::create('config/security_admin.yaml', '/app/config/security_admin.yaml', $security2),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        $rules = $mapping->firewallRules();
        self::assertContains('^/api', $rules);
        self::assertContains('^/admin', $rules);
    }

    public function test_mapping_stage_merges_access_control_from_multiple_config_files(): void
    {
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $config1 = "access_control:\n    - path: ^/admin\n      roles: ROLE_ADMIN\n";
        $config2 = "access_control:\n    - path: ^/api\n      roles: ROLE_USER\n";

        $auditContext->setProjectFiles([
            ProjectFile::create('config/security.yaml', '/app/config/security.yaml', $config1),
            ProjectFile::create('config/routes.yaml', '/app/config/routes.yaml', $config2),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        $routeMap = $mapping->routeAccessMap();
        self::assertArrayHasKey('^/admin', $routeMap);
        self::assertArrayHasKey('^/api', $routeMap);
    }

    public function test_mapping_stage_trims_firewall_pattern_whitespace(): void
    {
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $content = "security:\n    firewalls:\n        main:\n            pattern: ^/api  \n";

        $auditContext->setProjectFiles([
            ProjectFile::create('config/security.yaml', '/app/config/security.yaml', $content),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertContains('^/api', $mapping->firewallRules());
    }

    public function test_mapping_stage_returns_empty_access_control_when_not_present(): void
    {
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditContext->setProjectFiles([
            ProjectFile::create('config/services.yaml', '/app/config/services.yaml', "services:\n    _defaults:\n        autowire: true\n"),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertEmpty($mapping->routeAccessMap());
    }

    public function test_mapping_stage_skips_path_roles_pairs_outside_access_control_block(): void
    {
        // Covers the early return when 'access_control' key is absent. The regex would
        // otherwise still match path:/roles: pairs from unrelated YAML — e.g., a routing file
        // with per-route role guards — which should not feed the access_control map.
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $content = "some_route:\n    path: /admin\n    roles: ROLE_ADMIN\n";

        $auditContext->setProjectFiles([
            ProjectFile::create('config/routes.yaml', '/app/config/routes.yaml', $content),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertEmpty($mapping->routeAccessMap());
    }

    public function test_mapping_stage_extracts_multiple_routes_from_access_control(): void
    {
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $content = "access_control:\n    - path: ^/admin\n      roles: ROLE_ADMIN\n    - path: ^/api\n      roles: ROLE_USER\n";

        $auditContext->setProjectFiles([
            ProjectFile::create('config/security.yaml', '/app/config/security.yaml', $content),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        $routeMap = $mapping->routeAccessMap();
        self::assertCount(2, $routeMap);
        self::assertArrayHasKey('^/admin', $routeMap);
        self::assertArrayHasKey('^/api', $routeMap);
    }

    public function test_mapping_stage_trims_path_whitespace_in_access_control(): void
    {
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $content = "access_control:\n    - path: ^/admin   \n      roles: ROLE_ADMIN\n";

        $auditContext->setProjectFiles([
            ProjectFile::create('config/security.yaml', '/app/config/security.yaml', $content),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertArrayHasKey('^/admin', $mapping->routeAccessMap());
        self::assertArrayNotHasKey('^/admin   ', $mapping->routeAccessMap());
    }

    public function test_mapping_stage_trims_roles_in_access_control(): void
    {
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $content = "access_control:\n    - path: ^/admin\n      roles: ROLE_ADMIN, ROLE_SUPER\n";

        $auditContext->setProjectFiles([
            ProjectFile::create('config/security.yaml', '/app/config/security.yaml', $content),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        $roles = $mapping->routeAccessMap()['^/admin'] ?? [];
        self::assertContains('ROLE_ADMIN', $roles);
        self::assertContains('ROLE_SUPER', $roles);
    }

    public function test_ingestion_stage_logs_warning_when_no_files_found(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('No files found in project', ['path' => $this->tmpDir]);

        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $scanner->method('scan')->willReturn([]);

        $ingestionStage = new IngestionStage($scanner, $logger);
        $auditContext = AuditContext::forProject($this->tmpDir);

        $ingestionStage->process($auditContext);
    }

    public function test_ingestion_stage_logs_info_on_completion(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $message, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$message, $ctx];
            },
        );

        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $scanner->method('scan')->willReturn([
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
        ]);

        $ingestionStage = new IngestionStage($scanner, $logger);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $ingestionStage->process($auditContext);

        self::assertSame(['Ingesting project files', ['path' => $this->tmpDir]], $infoLogs[0]);
        self::assertSame(['Ingestion complete', ['files' => 1, 'lines' => 1]], $infoLogs[1]);
    }

    public function test_mapping_stage_logs_warning_when_no_files(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('No files to map');
        $logger->expects(self::never())->method('info');

        $mappingStage = new MappingStage($logger);
        $auditContext = AuditContext::forProject($this->tmpDir);

        $mappingStage->process($auditContext);
    }

    public function test_mapping_stage_logs_info_on_completion(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $message, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$message, $ctx];
            },
        );

        $mappingStage = new MappingStage($logger);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', '<?php class UserController {}'),
        ]);

        $mappingStage->process($auditContext);

        self::assertSame('Mapping complete', $infoLogs[0][0]);
        $ctx = $infoLogs[0][1];
        self::assertIsString($ctx['summary']);
        self::assertStringContainsString('Controllers: 1', $ctx['summary']);
        self::assertSame(1, $ctx['unprotected_controllers']);
    }

    public function test_audit_stage_logs_warning_when_no_files_to_audit(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('No files to audit, skipping');
        $logger->expects(self::never())->method('info');

        $auditStage = new AuditStage($this->makeOrchestrator(), $logger);
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditStage->process($auditContext);
    }

    public function test_audit_stage_logs_warning_when_mapping_not_available(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('Mapping not available, skipping audit stage');
        $logger->expects(self::never())->method('info');

        $auditStage = new AuditStage($this->makeOrchestrator(), $logger);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
        ]);
        // No mapping set

        $auditStage->process($auditContext);
    }

    public function test_audit_stage_logs_info_on_completion(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $message, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$message, $ctx];
            },
        );

        $attackerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(LLMResponse::create('[]', 0, 0, 'stub', 'end_turn'));
        $reviewerLlm = self::createStub(LLMClientInterface::class);

        $auditStage = new AuditStage($this->makeOrchestrator($attackerLlm, $reviewerLlm), $logger);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
        ]);
        $auditContext->setMapping(SymfonyMapping::create());

        $auditStage->process($auditContext);

        $stageCompleteLogs = array_values(array_filter(
            $infoLogs,
            static fn (array $entry): bool => 'Audit stage complete' === $entry[0],
        ));

        self::assertCount(1, $stageCompleteLogs);
        self::assertSame([
            'vulnerabilities' => 0,
            'validated' => 0,
            'critical' => 0,
            'risk_score' => 0,
        ], $stageCompleteLogs[0][1]);
    }

    public function test_mapping_stage_returns_immediately_and_sets_empty_mapping_when_no_files(): void
    {
        // Tests ReturnRemoval on `return;` after the no-files guard.
        // If removed, the code proceeds to array_filter etc. on empty array — result is same mapping,
        // but the logger.warning call distinguishes the paths.
        $mappingStage = new MappingStage(new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertSame(0, $mapping->totalFiles());
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/stages_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    protected function tearDown(): void
    {
        $this->rmdirRecursive($this->tmpDir);
    }

    private function makeOrchestrator(
        ?LLMClientInterface $attackerLlm = null,
        ?LLMClientInterface $reviewerLlm = null,
    ): AuditOrchestrator {
        return new AuditOrchestrator(
            attackerAgent: new AttackerAgent(
                llmClient: $attackerLlm ?? self::createStub(LLMClientInterface::class),
                attackerPromptBuilder: new AttackerPromptBuilder(),
                vulnerabilityFactory: new VulnerabilityFactory(new NullLogger()),
                attackerCache: new NullAttackerCache(),
                logger: new NullLogger(),
            ),
            reviewerAgent: new ReviewerAgent(
                llmClient: $reviewerLlm ?? self::createStub(LLMClientInterface::class),
                reviewerPromptBuilder: new ReviewerPromptBuilder(),
                logger: new NullLogger(),
            ),
            logger: new NullLogger(),
        );
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
