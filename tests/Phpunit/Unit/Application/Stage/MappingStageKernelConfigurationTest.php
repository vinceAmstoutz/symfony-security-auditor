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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ApplicationAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\SymfonyMappingContextRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

final class MappingStageKernelConfigurationTest extends TestCase
{
    private const string FIREWALLS = "security:\n    firewalls:\n        main:\n            pattern: ^/\n";

    private const string ACCESS_CONTROL = "security:\n    access_control:\n        - { path: ^/admin, roles: ROLE_ADMIN }\n";

    /**
     * @param array<string, string> $files
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('configurationTheKernelLoadsCases')]
    public function test_access_control_of_every_file_the_production_kernel_loads_reaches_the_mapping(array $files): void
    {
        $symfonyMapping = $this->mappingOf($files);

        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $symfonyMapping->routeAccessMap());
        self::assertSame(['^/'], $symfonyMapping->toApplicationSecurityMap()->perimeterRules());
    }

    /** @return iterable<string, array{0: array<string, string>}> */
    public static function configurationTheKernelLoadsCases(): iterable
    {
        yield 'another package file' => [[
            'config/packages/security.yaml' => self::FIREWALLS,
            'config/packages/security_access.yaml' => self::ACCESS_CONTROL,
        ]];
        yield 'the production block of another package file' => [[
            'config/packages/security.yaml' => self::FIREWALLS,
            'config/packages/app.yaml' => "when@prod:\n".preg_replace('/^/m', '    ', self::ACCESS_CONTROL),
        ]];
        yield 'a file the security package imports' => [[
            'config/packages/security.yaml' => "imports:\n    - { resource: 'security/access_control.yaml' }\n".self::FIREWALLS,
            'config/packages/security/access_control.yaml' => self::ACCESS_CONTROL,
        ]];
        yield 'the files a wildcard import of the security package names' => [[
            'config/packages/security.yaml' => "imports:\n    - { resource: 'security/*.yaml' }\n".self::FIREWALLS,
            'config/packages/security/access_control.yaml' => self::ACCESS_CONTROL,
            'config/packages/security/password_hashers.yaml' => "security:\n    password_hashers:\n        App\\Entity\\User: auto\n",
        ]];
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_project_whose_security_configuration_is_the_security_package_maps_as_it_did_before(): void
    {
        $symfonyMapping = $this->mappingOf($this->flexProject());

        self::assertSame(['^/login' => ['PUBLIC_ACCESS'], '^/admin' => ['ROLE_ADMIN'], '^/profile' => ['ROLE_USER', 'methods: GET|POST']], $symfonyMapping->routeAccessMap());
        self::assertSame(['^/(_(profiler|wdt)|css|images|js)/ (security: false)', 'main'], $symfonyMapping->toApplicationSecurityMap()->perimeterRules());
        self::assertSame([], $symfonyMapping->unreadableConfigurationFiles());
    }

    private function adminController(): string
    {
        return <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\HttpFoundation\Response;
            use Symfony\Component\Routing\Attribute\Route;
            final class AdminController extends AbstractController
            {
                #[Route('/admin/users', methods: ['GET'])]
                public function users(): Response { return new Response(''); }
            }
            PHP;
    }

    /**
     * @return array<string, string>
     */
    private function flexProject(): array
    {
        return [
            'config/packages/cache.yaml' => "framework:\n    cache: ~\n",
            'config/packages/doctrine.yaml' => "doctrine:\n    dbal:\n        url: '%env(resolve:DATABASE_URL)%'\nwhen@test:\n    doctrine:\n        dbal:\n            dbname_suffix: '_test'\nwhen@prod:\n    doctrine:\n        orm:\n            auto_generate_proxy_classes: false\n",
            'config/packages/framework.yaml' => "framework:\n    secret: '%env(APP_SECRET)%'\n    session: true\nwhen@test:\n    framework:\n        test: true\n",
            'config/packages/security.yaml' => <<<'YAML'
                security:
                    password_hashers:
                        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'
                    providers:
                        app_user_provider:
                            entity:
                                class: App\Entity\User
                                property: email
                    firewalls:
                        dev:
                            pattern: ^/(_(profiler|wdt)|css|images|js)/
                            security: false
                        main:
                            lazy: true
                            provider: app_user_provider
                            form_login:
                                login_path: app_login
                                check_path: app_login
                    access_control:
                        - { path: ^/login, roles: PUBLIC_ACCESS }
                        - { path: ^/admin, roles: ROLE_ADMIN }
                        - { path: ^/profile, roles: ROLE_USER, methods: [GET, POST] }
                when@test:
                    security:
                        password_hashers:
                            Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface:
                                algorithm: auto
                                cost: 4
                YAML,
            'config/packages/symfony_security_auditor.yaml' => "symfony_security_auditor:\n    model: 'claude-opus-5'\n",
            'config/packages/twig.yaml' => "twig:\n    file_name_pattern: '*.twig'\n",
            'config/packages/prod/doctrine.yaml' => "doctrine:\n    orm:\n        query_cache_driver:\n            type: pool\n",
            'config/services.yaml' => "services:\n    _defaults:\n        autowire: true\n    App\\:\n        resource: '../src/'\n",
            'config/routes.yaml' => "controllers:\n    resource: routing.controllers\n",
        ];
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('pathsInsideAnApplicationOfAMonorepoCases')]
    public function test_a_run_narrowed_to_an_application_of_a_monorepo_reads_that_applications_configuration(array $scanPaths): void
    {
        $symfonyMapping = $this->mappingOf([
            'apps/api/config/packages/security.yaml' => self::FIREWALLS.substr(self::ACCESS_CONTROL, \strlen("security:\n")),
            'apps/api/src/Controller/AdminController.php' => '<?php',
            'apps/web/config/packages/security.yaml' => "security:\n    firewalls:\n        web:\n            pattern: ^/web\n    access_control:\n        - { path: ^/admin, roles: ROLE_WEB }\n",
        ], $scanPaths);

        self::assertSame([], $symfonyMapping->routeAccessMap());
        self::assertSame([], $symfonyMapping->toApplicationSecurityMap()->perimeterRules());
        self::assertEquals(['apps/api/' => new ApplicationAccessControl(['^/admin' => ['ROLE_ADMIN']], ['^/'])], $symfonyMapping->applicationAccessControls());
        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $symfonyMapping->routeAccessMapFor('apps/api/src/Controller/AdminController.php'));
    }

    /** @return iterable<string, array{0: list<string>}> */
    public static function pathsInsideAnApplicationOfAMonorepoCases(): iterable
    {
        yield 'the application' => [['apps/api']];
        yield 'the application, spelled loosely' => [['./apps//api/']];
        yield 'a folder of the application' => [['apps/api/src/Controller']];
        yield 'a file of the application' => [['apps/api/src/Controller/AdminController.php']];
        yield 'a folder outside any application, then the application' => [['tools', 'apps/api']];
        yield 'two folders of the application' => [['apps/api/src', 'apps/api/config']];
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_monorepo_audited_whole_reads_no_application_configuration(): void
    {
        $symfonyMapping = $this->mappingOf([
            'apps/api/config/packages/security.yaml' => self::FIREWALLS.substr(self::ACCESS_CONTROL, \strlen("security:\n")),
        ]);

        self::assertSame([], $symfonyMapping->routeAccessMap());
        self::assertSame([], $symfonyMapping->applicationAccessControls());
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_the_rules_of_an_application_govern_its_routes_and_the_project_rules_the_others(): void
    {
        $symfonyMapping = $this->mappingOf([
            'apps/api/config/packages/prod/security.yaml' => "security:\n    access_control:\n        - { path: ^/api, roles: ROLE_PROD }\n",
            'apps/api/config/packages/security.yaml' => "security:\n    access_control:\n        - { path: ^/api, roles: ROLE_API }\n",
            'config/packages/security.yaml' => "security:\n    access_control:\n        - { path: ^/root, roles: ROLE_ROOT }\n",
        ], ['apps/api']);

        self::assertSame(['^/root' => ['ROLE_ROOT']], $symfonyMapping->routeAccessMap());
        self::assertSame(['^/root' => ['ROLE_ROOT']], $symfonyMapping->routeAccessMapFor('src/Controller/HomeController.php'));
        self::assertSame(['^/root' => ['ROLE_ROOT']], $symfonyMapping->routeAccessMapFor('apps/web/src/Controller/HomeController.php'));
        self::assertSame(['^/api' => ['ROLE_API', 'or: ROLE_PROD']], $symfonyMapping->routeAccessMapFor('apps/api/src/Controller/ApiController.php'));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_run_narrowed_to_a_nested_application_reads_the_nearest_application_configuration(): void
    {
        $symfonyMapping = $this->mappingOf([
            'apps/config/packages/security.yaml' => "security:\n    access_control:\n        - { path: ^/outer, roles: ROLE_OUTER }\n",
            'apps/api/config/packages/security.yaml' => self::ACCESS_CONTROL,
        ], ['apps/api/src']);

        self::assertSame(['apps/api/'], array_keys($symfonyMapping->applicationAccessControls()));
        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $symfonyMapping->routeAccessMapFor('apps/api/src/Controller/AdminController.php'));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_route_takes_the_rules_of_the_nearest_of_two_nested_applications(): void
    {
        $symfonyMapping = $this->mappingOf([
            'apps/config/packages/security.yaml' => "security:\n    access_control:\n        - { path: ^/outer, roles: ROLE_OUTER }\n",
            'apps/api/config/packages/security.yaml' => self::ACCESS_CONTROL,
        ], ['apps/api', 'apps/tools']);

        self::assertSame(['apps/api/', 'apps/'], array_keys($symfonyMapping->applicationAccessControls()));
        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $symfonyMapping->routeAccessMapFor('apps/api/src/Controller/AdminController.php'));
        self::assertSame(['^/outer' => ['ROLE_OUTER']], $symfonyMapping->routeAccessMapFor('apps/tools/src/Controller/ToolController.php'));
    }

    /**
     * @param array<string, string> $files
     * @param list<string>          $scanPaths
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('applicationsTheRulesOfAnotherMustNotCoverCases')]
    public function test_the_rules_of_another_application_or_of_the_project_never_cover_the_route_of_an_application(array $files, array $scanPaths): void
    {
        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingOf($files + [
            'apps/api/config/packages/security.yaml' => self::FIREWALLS,
            'apps/api/src/Controller/AdminController.php' => $this->adminController(),
        ], $scanPaths));

        self::assertStringContainsString('- GET /admin/users — apps/api/src/Controller/AdminController.php::users — LACKS_ACCESS_CHECK', $rendered);
    }

    /** @return iterable<string, array{0: array<string, string>, 1: list<string>}> */
    public static function applicationsTheRulesOfAnotherMustNotCoverCases(): iterable
    {
        yield 'another application the run is narrowed to' => [['apps/admin/config/packages/security.yaml' => self::FIREWALLS.substr(self::ACCESS_CONTROL, \strlen("security:\n"))], ['apps/api', 'apps/admin']];
        yield 'the project' => [['config/packages/security.yaml' => self::FIREWALLS.substr(self::ACCESS_CONTROL, \strlen("security:\n"))], ['apps/api']];
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_the_rules_of_an_application_cover_its_own_route(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingOf([
            'apps/api/config/packages/security.yaml' => self::FIREWALLS,
            'apps/admin/config/packages/security.yaml' => self::FIREWALLS.substr(self::ACCESS_CONTROL, \strlen("security:\n")),
            'apps/admin/src/Controller/AdminController.php' => $this->adminController(),
        ], ['apps/api', 'apps/admin']));

        self::assertStringContainsString('- GET /admin/users — apps/admin/src/Controller/AdminController.php::users — COVERED_BY access_control[ROLE_ADMIN]', $rendered);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_a_configuration_file_the_kernel_loads_and_the_audit_cannot_read_is_reported(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                'A configuration file the production application loads could not be read, so the security rules it may hold are missing from the mapping',
                self::callback(static fn (array $context): bool => 'config/packages/security.yaml' === $context['file'] && \is_string($context['reason']) && str_starts_with($context['reason'], 'it is not valid YAML: ')),
            );

        $symfonyMapping = $this->mappingOf([
            'config/packages/security.yaml' => "security: [\n",
            'config/packages/security_access.yaml' => self::ACCESS_CONTROL,
        ], logger: $logger);

        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $symfonyMapping->routeAccessMap());
        self::assertSame(['config/packages/security.yaml'], $symfonyMapping->unreadableConfigurationFiles());
    }

    /**
     * @param array<string, string> $packageFiles
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('packageFilesHoldingNoSecurityConfigurationCases')]
    public function test_a_package_file_holding_no_security_configuration_is_never_reported_unread(array $packageFiles): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('warning');

        $symfonyMapping = $this->mappingOf($packageFiles + ['config/packages/security.yaml' => self::FIREWALLS.substr(self::ACCESS_CONTROL, \strlen("security:\n"))], logger: $logger);

        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $symfonyMapping->routeAccessMap());
        self::assertSame([], $symfonyMapping->unreadableConfigurationFiles());
        self::assertSame('', SymfonyMappingContextRenderer::renderUnreadableConfiguration($symfonyMapping));
    }

    /** @return iterable<string, array{0: array<string, string>}> */
    public static function packageFilesHoldingNoSecurityConfigurationCases(): iterable
    {
        yield 'a messenger setup with a custom tag' => [['config/packages/messenger.yaml' => "framework:\n    messenger:\n        transports:\n            async: '%env(MESSENGER_TRANSPORT_DSN)%'\nservices:\n    App\\Handler\\Chain:\n        arguments: [!tagged_iterator app.handler]\n"]];

        $apiDocumentation = "nelmio_api_doc:\n    documentation:\n        info:\n            title: X\n        paths:\n";
        foreach (range(0, 2999) as $index) {
            $apiDocumentation .= \sprintf("            /api/thing%d:\n                get:\n                    summary: 'Read thing number %d of the catalog with a long description'\n                    responses:\n                        '200':\n                            description: OK\n", $index, $index);
        }

        yield 'an API documentation too large to read' => [['config/packages/nelmio_api_doc.yaml' => $apiDocumentation]];
    }

    /**
     * @param array<string, string> $files
     * @param list<string>          $scanPaths
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private function mappingOf(array $files, array $scanPaths = [], LoggerInterface $logger = new NullLogger()): SymfonyMapping
    {
        $projectFiles = [];
        foreach ($files as $relativePath => $content) {
            $projectFiles[] = ProjectFile::create($relativePath, '/app/'.$relativePath, $content);
        }

        $auditContext = AuditContext::forProject(sys_get_temp_dir(), $scanPaths);
        $auditContext->setProjectFiles($projectFiles);

        (new MappingStage($logger, new PhpParserControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser()))->process($auditContext);

        $symfonyMapping = $auditContext->mapping();
        self::assertInstanceOf(SymfonyMapping::class, $symfonyMapping);

        return $symfonyMapping;
    }
}
