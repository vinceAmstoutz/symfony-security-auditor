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

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\ErrorHandler\BufferingLogger;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\AuditStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ControllerAccessControlParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullSecurityConfigParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\VoterCapabilityParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

final class StagesTest extends TestCase
{
    private string $tmpDir;

    public function test_ingestion_stage_has_correct_name(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $ingestionStage = new IngestionStage($scanner, new NullLogger());

        self::assertSame('ingestion', $ingestionStage->name());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
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

    /**
     * @throws InvalidAuditContextException
     */
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

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_ingestion_stage_restricts_files_to_context_scan_paths(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $scanner->method('scan')->willReturn([
            ProjectFile::create('apps/api/src/A.php', '/app/apps/api/src/A.php', '<?php'),
            ProjectFile::create('apps/web/src/B.php', '/app/apps/web/src/B.php', '<?php'),
        ]);

        $ingestionStage = new IngestionStage($scanner, new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir, ['apps/api']);

        $ingestionStage->process($auditContext);

        self::assertCount(1, $auditContext->projectFiles());
        self::assertSame('apps/api/src/A.php', $auditContext->projectFiles()[0]->relativePath());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_ingestion_stage_filters_to_git_changed_files_and_logs_the_diff(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $scanner->method('scan')->willReturn([
            ProjectFile::create('src/ChangedA.php', '/app/src/ChangedA.php', '<?php'),
            ProjectFile::create('src/ChangedB.php', '/app/src/ChangedB.php', '<?php'),
            ProjectFile::create('src/Unchanged.php', '/app/src/Unchanged.php', '<?php'),
        ]);

        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/ChangedA.php', 'src/ChangedB.php']);

        $bufferingLogger = new BufferingLogger();
        $ingestionStage = new IngestionStage($scanner, $bufferingLogger, $gitChangedFilesResolver);
        $auditContext = AuditContext::forProject($this->tmpDir, [], false, 'main');

        $ingestionStage->process($auditContext);

        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $auditContext->projectFiles());
        self::assertContains('src/ChangedA.php', $paths);
        self::assertContains('src/ChangedB.php', $paths);
        self::assertNotContains('src/Unchanged.php', $paths);

        self::assertSame(
            ['ref' => 'main', 'changed_in_diff' => 2, 'kept_after_intersection' => 2, 'dropped' => 1],
            $this->contextOf($bufferingLogger->cleanLogs(), 'Diff filter applied'),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_ingestion_stage_populates_mapping_files_with_the_full_scan_scope_even_when_diff_filtering_project_files(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $scanner->method('scan')->willReturn([
            ProjectFile::create('src/ChangedA.php', '/app/src/ChangedA.php', '<?php'),
            ProjectFile::create('src/Unchanged.php', '/app/src/Unchanged.php', '<?php'),
        ]);

        $gitChangedFilesResolver = self::createStub(GitChangedFilesResolverInterface::class);
        $gitChangedFilesResolver->method('changedSince')->willReturn(['src/ChangedA.php']);

        $ingestionStage = new IngestionStage($scanner, new NullLogger(), $gitChangedFilesResolver);
        $auditContext = AuditContext::forProject($this->tmpDir, [], false, 'main');

        $ingestionStage->process($auditContext);

        $projectFilePaths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $auditContext->projectFiles());
        $mappingFilePaths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $auditContext->mappingFiles());

        self::assertSame(['src/ChangedA.php'], $projectFilePaths);
        self::assertSame(['src/ChangedA.php', 'src/Unchanged.php'], $mappingFilePaths);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_ingestion_stage_does_not_filter_when_no_resolver_even_with_since_ref(): void
    {
        $scanner = self::createStub(ProjectFileScannerInterface::class);
        $scanner->method('scan')->willReturn([
            ProjectFile::create('src/Changed.php', '/app/src/Changed.php', '<?php'),
            ProjectFile::create('src/Unchanged.php', '/app/src/Unchanged.php', '<?php'),
        ]);

        $ingestionStage = new IngestionStage($scanner, new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir, [], false, 'main');

        $ingestionStage->process($auditContext);

        self::assertCount(2, $auditContext->projectFiles());
    }

    public function test_mapping_stage_has_correct_name(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());

        self::assertSame('mapping', $mappingStage->name());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_mapping_stage_routes_controllers_through_the_access_control_parser(): void
    {
        $controllerFile = ProjectFile::create('src/Controller/AdminController.php', '/app/x', '<?php class AdminController {}');
        $protected = new RouteAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'edit',
            routePath: '/admin/edit',
            routeMethods: ['POST'],
            hasRouteAttribute: true,
            methodLevelIsGranted: ['ROLE_ADMIN'],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
        );
        $unprotected = new RouteAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'leak',
            routePath: '/admin/leak',
            routeMethods: [],
            hasRouteAttribute: true,
            methodLevelIsGranted: [],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
        );
        $parser = new readonly class([$protected, $unprotected]) implements ControllerAccessControlParserInterface {
            /** @param list<RouteAccessControl> $entries */
            public function __construct(private array $entries) {}

            #[Override]
            public function parse(ProjectFile $projectFile): array
            {
                return $this->entries;
            }
        };

        $mappingStage = new MappingStage(new NullLogger(), $parser, new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([$controllerFile]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertSame([$protected, $unprotected], $mapping->routeAccessControls());
        self::assertSame([$unprotected], $mapping->controllersWithoutAccessCheck());
        self::assertSame(2, $auditContext->getMeta('mapping.routes'));
        self::assertSame(1, $auditContext->getMeta('mapping.routes_without_access_check'));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_mapping_stage_aggregates_route_access_controls_from_multiple_controllers(): void
    {
        $controllerA = ProjectFile::create('src/Controller/AController.php', '/app/A', '<?php class AController {}');
        $controllerB = ProjectFile::create('src/Controller/BController.php', '/app/B', '<?php class BController {}');
        $entryA = new RouteAccessControl('src/Controller/AController.php', 'a', '/a', ['GET'], true, ['ROLE_A'], false, false);
        $entryB = new RouteAccessControl('src/Controller/BController.php', 'b', '/b', ['POST'], true, ['ROLE_B'], false, false);

        $parser = new readonly class($entryA, $entryB) implements ControllerAccessControlParserInterface {
            public function __construct(private RouteAccessControl $entryA, private RouteAccessControl $entryB) {}

            #[Override]
            public function parse(ProjectFile $projectFile): array
            {
                return 'src/Controller/AController.php' === $projectFile->relativePath() ? [$this->entryA] : [$this->entryB];
            }
        };

        $mappingStage = new MappingStage(new NullLogger(), $parser, new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([$controllerA, $controllerB]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertSame([$entryA, $entryB], $mapping->routeAccessControls());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_mapping_stage_routes_voters_through_the_voter_capability_parser(): void
    {
        $voterFileA = ProjectFile::create('src/Security/UserVoter.php', '/app/U', '<?php class UserVoter {}');
        $voterFileB = ProjectFile::create('src/Security/CommentVoter.php', '/app/C', '<?php class CommentVoter {}');
        $capabilityA = new VoterCapability('src/Security/UserVoter.php', 'UserVoter', ['EDIT'], ['User']);
        $capabilityB = new VoterCapability('src/Security/CommentVoter.php', 'CommentVoter', ['VIEW'], ['Comment']);
        $parser = new readonly class($capabilityA, $capabilityB) implements VoterCapabilityParserInterface {
            public function __construct(private VoterCapability $capA, private VoterCapability $capB) {}

            #[Override]
            public function parse(ProjectFile $projectFile): ?VoterCapability
            {
                return match ($projectFile->relativePath()) {
                    'src/Security/UserVoter.php' => $this->capA,
                    'src/Security/CommentVoter.php' => $this->capB,
                    default => null,
                };
            }
        };

        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), $parser, new NullFormBindingParser(), new NullSecurityConfigParser());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([$voterFileA, $voterFileB]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertSame([$capabilityA, $capabilityB], $mapping->voterCapabilities());
        self::assertSame(2, $auditContext->getMeta('mapping.voter_capabilities'));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_mapping_stage_skips_null_voter_parser_results(): void
    {
        $voterFile = ProjectFile::create('src/Security/SilentVoter.php', '/app/x', '<?php class SilentVoter {}');
        $parser = new readonly class implements VoterCapabilityParserInterface {
            #[Override]
            public function parse(ProjectFile $projectFile): ?VoterCapability
            {
                return null;
            }
        };

        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), $parser, new NullFormBindingParser(), new NullSecurityConfigParser());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([$voterFile]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertSame([], $mapping->voterCapabilities());
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
    public function test_mapping_stage_routes_controllers_through_the_form_binding_parser(): void
    {
        $controllerA = ProjectFile::create('src/Controller/UserController.php', '/app/U', '<?php class UserController {}');
        $controllerB = ProjectFile::create('src/Controller/AdminController.php', '/app/A', '<?php class AdminController {}');
        $bindingA = new FormBinding('src/Controller/UserController.php', 'edit', 'App\\Form\\UserType');
        $bindingB = new FormBinding('src/Controller/AdminController.php', 'create', 'App\\Form\\AdminType');

        $parser = new readonly class($bindingA, $bindingB) implements FormBindingParserInterface {
            public function __construct(private FormBinding $a, private FormBinding $b) {}

            #[Override]
            public function parse(ProjectFile $projectFile): array
            {
                return match ($projectFile->relativePath()) {
                    'src/Controller/UserController.php' => [$this->a],
                    'src/Controller/AdminController.php' => [$this->b],
                    default => [],
                };
            }
        };

        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), $parser, new NullSecurityConfigParser());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([$controllerA, $controllerB]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertSame([$bindingA, $bindingB], $mapping->formBindings());
        self::assertSame(2, $auditContext->getMeta('mapping.form_bindings'));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_creates_mapping_from_project_files(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());

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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_builds_the_mapping_from_the_full_scan_scope_not_the_diff_filtered_project_files(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', '<?php class UserController {}'),
        ]);
        $auditContext->setMappingFiles([
            ProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', '<?php class UserController {}'),
            ProjectFile::create('src/Security/UserVoter.php', '/app/src/Security/UserVoter.php', '<?php class UserVoter {}'),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertCount(1, $mapping->controllers());
        self::assertCount(1, $mapping->voters());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_mapping_stage_handles_empty_file_list(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());

        $auditContext = AuditContext::forProject($this->tmpDir);
        // No files set

        $mappingStage->process($auditContext);

        self::assertNotNull($auditContext->mapping());
        self::assertSame(0, $auditContext->mapping()->totalFiles());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_extracts_security_config(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser());

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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_maps_route_access_control_and_form_bindings_for_a_live_component_extending_abstract_controller(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new PhpParserControllerAccessControlParser(), new NullVoterCapabilityParser(), new PhpParserFormBindingParser(), new NullSecurityConfigParser());

        $source = <<<'PHP'
            <?php
            namespace App\Twig\Components;
            use App\Form\CartCheckoutType;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\UX\LiveComponent\Attribute\AsLiveComponent;
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            #[AsLiveComponent]
            final class Cart extends AbstractController {
                #[Route('/cart/checkout')]
                public function checkout(): void {
                    $this->denyAccessUnlessGranted('ROLE_ADMIN');
                    $form = $this->createForm(CartCheckoutType::class);
                }
            }
            PHP;

        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/Twig/Components/Cart.php', '/app/src/Twig/Components/Cart.php', $source),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertCount(1, $mapping->routeAccessControls());
        self::assertSame('checkout', $mapping->routeAccessControls()[0]->methodName());
        self::assertCount(1, $mapping->formBindingsForController('src/Twig/Components/Cart.php'));
    }

    public function test_audit_stage_has_correct_name(): void
    {
        $auditStage = new AuditStage($this->makeOrchestrator(), new NullLogger());

        self::assertSame('audit', $auditStage->name());
    }

    /**
     * @throws InvalidAuditContextException
     */
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_audit_stage_calls_orchestrator_when_ready(): void
    {
        $attackerLlm = self::createStub(LLMClientInterface::class);
        $reviewerLlm = self::createStub(LLMClientInterface::class);
        $attackerLlm->method('complete')->willReturn(LLMResponse::of('[]', 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)));

        $auditStage = new AuditStage($this->makeOrchestrator($attackerLlm, $reviewerLlm), new NullLogger());
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
        ]);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

        $auditStage->process($auditContext);

        // Orchestrator ran (writes the audit.iterations meta) and finished cleanly.
        self::assertNotNull($auditContext->getMeta('audit.iterations'));
    }

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_sets_meta_counts(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_sets_no_voter_controllers_to_zero_when_all_secured(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_processes_all_config_files_not_just_first(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_merges_access_control_from_multiple_config_files(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_appends_conflicting_access_control_rules_across_config_files_instead_of_overwriting(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $config1 = "access_control:\n    - path: ^/admin\n      roles: ROLE_ADMIN\n";
        $config2 = "access_control:\n    - path: ^/admin\n      ips: 10.0.0.0/8\n";

        $auditContext->setProjectFiles([
            ProjectFile::create('config/packages/security.yaml', '/app/config/packages/security.yaml', $config1),
            ProjectFile::create('config/packages/dev/security.yaml', '/app/config/packages/dev/security.yaml', $config2),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        $rule = $mapping->routeAccessMap()['^/admin'];
        self::assertContains('ROLE_ADMIN', $rule);
        self::assertContains('or: ips: 10.0.0.0/8', $rule);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_trims_firewall_pattern_whitespace(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_returns_empty_access_control_when_not_present(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $auditContext->setProjectFiles([
            ProjectFile::create('config/services.yaml', '/app/config/services.yaml', "services:\n    _defaults:\n        autowire: true\n"),
        ]);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertEmpty($mapping->routeAccessMap());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_skips_path_roles_pairs_outside_access_control_block(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_extracts_multiple_routes_from_access_control(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_trims_path_whitespace_in_access_control(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_trims_roles_in_access_control(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     */
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

    /**
     * @throws InvalidProjectFileException
     * @throws InvalidAuditContextException
     */
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

    /**
     * @throws InvalidAuditContextException
     */
    public function test_mapping_stage_logs_warning_when_no_files(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with('No files to map');
        $logger->expects(self::never())->method('info');

        $mappingStage = new MappingStage($logger, new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $mappingStage->process($auditContext);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_mapping_stage_logs_info_on_completion(): void
    {
        $infoLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('info')->willReturnCallback(
            static function (string $message, array $ctx = []) use (&$infoLogs): void {
                $infoLogs[] = [$message, $ctx];
            },
        );

        $mappingStage = new MappingStage($logger, new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());
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

    /**
     * @throws InvalidAuditContextException
     */
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

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
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
        $attackerLlm->method('complete')->willReturn(LLMResponse::of('[]', 'stub', 'end_turn', TokenUsageSnapshot::of(0, 0)));
        $reviewerLlm = self::createStub(LLMClientInterface::class);

        $auditStage = new AuditStage($this->makeOrchestrator($attackerLlm, $reviewerLlm), $logger);
        $auditContext = AuditContext::forProject($this->tmpDir);
        $auditContext->setProjectFiles([
            ProjectFile::create('src/A.php', '/app/src/A.php', '<?php'),
        ]);
        $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));

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

    /**
     * @throws InvalidAuditContextException
     */
    public function test_mapping_stage_returns_immediately_and_sets_empty_mapping_when_no_files(): void
    {
        $mappingStage = new MappingStage(new NullLogger(), new NullControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new NullSecurityConfigParser());
        $auditContext = AuditContext::forProject($this->tmpDir);

        $mappingStage->process($auditContext);

        $mapping = $auditContext->mapping();
        self::assertNotNull($mapping);
        self::assertSame(0, $mapping->totalFiles());
    }

    /**
     * @param array<mixed> $logs
     *
     * @return array<mixed>
     */
    private function contextOf(array $logs, string $message): array
    {
        foreach ($logs as $log) {
            self::assertIsArray($log);
            if ($message === ($log[1] ?? null)) {
                $context = $log[2] ?? [];
                self::assertIsArray($context);

                return $context;
            }
        }

        self::fail(\sprintf('No log entry with message "%s"', $message));
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/stages_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
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
                new AttackerLlmCollaborators(
                    $attackerLlm ?? self::createStub(LLMClientInterface::class),
                    new AttackerPromptBuilder(),
                    new VulnerabilityFactory(new NullLogger(), Validation::createValidator()),
                    new NullCodeSlicer(),
                ),
                new AttackerScanCollaborators(
                    new NullAttackerCache(),
                    new NullStaticPreScanner(),
                    new NullProgressReporter(),
                ),
                new AttackerAnalysisSettings(),
                new NullLogger(),
            ),
            reviewerAgent: new ReviewerAgent(
                new ReviewerAgentCollaborators(
                    $reviewerLlm ?? self::createStub(LLMClientInterface::class),
                    new ReviewerPromptBuilder(),
                    new NullLogger(),
                ),
                new ReviewerModeConfiguration(),
            ),
            logger: new NullLogger(),
            auditLoopSettings: new AuditLoopSettings(),
            progressReporter: new NullProgressReporter(),
        );
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
