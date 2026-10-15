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
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\SymfonyMappingContextRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

final class MappingStageAccessControlOrderTest extends TestCase
{
    private const string USERS = '- GET /admin/users — src/Controller/AdminController.php::users — ';

    private const string EXPORT = '- ANY /admin/export — src/Controller/AdminController.php::export — ';

    private const string AB = '- GET,POST /admin/a/b — src/Controller/AdminController.php::ab — ';

    private const string ADMIN_CONTROLLER = <<<'PHP'
        <?php
        namespace App\Controller;
        use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
        use Symfony\Component\HttpFoundation\Response;
        use Symfony\Component\Routing\Attribute\Route;
        final class AdminController extends AbstractController
        {
            #[Route('/admin/users', name: 'admin_users', methods: ['GET'])]
            public function users(): Response { return new Response(''); }
            #[Route('/admin/export', name: 'admin_export')]
            public function export(): Response { return new Response(''); }
            #[Route('/admin/a/b', name: 'admin_ab', methods: ['GET', 'POST'])]
            public function ab(): Response { return new Response(''); }
        }
        PHP;

    /**
     * @param array{0: string, 1: string, 2: string} $expectedLabels
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('accessControlCases')]
    public function test_each_route_is_labelled_by_the_first_access_control_rule_symfony_applies_to_it(string $accessControl, array $expectedLabels): void
    {
        self::assertSame([
            self::USERS.$expectedLabels[0],
            self::EXPORT.$expectedLabels[1],
            self::AB.$expectedLabels[2],
        ], $this->routeLines($accessControl));
    }

    /** @return iterable<string, array{0: string, 1: array{0: string, 1: string, 2: string}}> */
    public static function accessControlCases(): iterable
    {
        $lacks = 'LACKS_ACCESS_CHECK';

        yield 'a path-only catch-all listed first' => ["        - { path: ^/ }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n", [$lacks, $lacks, $lacks]];
        yield 'a route-only rule listed first' => ["        - { route: admin_users }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n", [$lacks, 'COVERED_BY access_control[ROLE_ADMIN]', 'COVERED_BY access_control[ROLE_ADMIN]']];
        yield 'an attributes-only rule listed first' => ["        - { path: ^/admin, attributes: { _format: json } }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n", [$lacks, $lacks, $lacks]];
        yield 'a rule for other methods, then a broader https rule, then the roles rule' => ["        - { path: ^/admin, roles: ROLE_ADMIN, methods: [POST] }\n        - { path: ^/, requires_channel: https }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n", [$lacks, $lacks, $lacks]];
        yield 'a catch-all https rule listed first' => ["        - { path: ^/, requires_channel: https }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n", [$lacks, $lacks, $lacks]];
        yield 'an ips rule' => ["        - { path: ^/admin, ips: [10.0.0.0/8] }\n", [$lacks, $lacks, $lacks]];
        yield 'a host rule' => ["        - { path: ^/admin, host: admin.example.com }\n", [$lacks, $lacks, $lacks]];
        yield 'a port rule' => ["        - { path: ^/admin, port: 8080 }\n", [$lacks, $lacks, $lacks]];
        yield 'a GET rule without roles before the roles rule' => ["        - { path: ^/admin, methods: [GET] }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n", [$lacks, $lacks, $lacks]];
        yield 'a PUT rule without roles before the roles rule' => ["        - { path: ^/admin, methods: [PUT] }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n", ['COVERED_BY access_control[methods: PUT,or: ROLE_ADMIN]', $lacks, 'COVERED_BY access_control[methods: PUT,or: ROLE_ADMIN]']];
        yield 'empty roles with an ips rule' => ["        - { path: ^/admin, roles: [], ips: [10.0.0.0/8] }\n", [$lacks, $lacks, $lacks]];
        yield 'blank roles with an ips rule' => ["        - { path: ^/admin, roles: '', ips: [10.0.0.0/8] }\n", [$lacks, $lacks, $lacks]];
        yield 'a role constant the parser cannot read, with an ips rule' => ["        - { path: ^/admin, roles: !php/const App\\Security\\Role::ADMIN, ips: [10.0.0.0/8] }\n", ['COVERED_BY access_control[ips: 10.0.0.0/8]', 'COVERED_BY access_control[ips: 10.0.0.0/8]', 'COVERED_BY access_control[ips: 10.0.0.0/8]']];
        yield 'a single role constant the parser cannot read, with an ips rule' => ["        - { path: ^/admin, role: !php/const App\\Security\\Role::ADMIN, ips: [10.0.0.0/8] }\n", ['COVERED_BY access_control[ips: 10.0.0.0/8]', 'COVERED_BY access_control[ips: 10.0.0.0/8]', 'COVERED_BY access_control[ips: 10.0.0.0/8]']];
        yield 'roles that read as nothing, with an ips rule' => ["        - { path: ^/admin, roles: ~, ips: [10.0.0.0/8] }\n", ['COVERED_BY access_control[ips: 10.0.0.0/8]', 'COVERED_BY access_control[ips: 10.0.0.0/8]', 'COVERED_BY access_control[ips: 10.0.0.0/8]']];
        yield 'an allow_if rule with an ips rule' => ["        - { path: ^/admin, allow_if: \"is_granted('ROLE_A')\", ips: [10.0.0.0/8] }\n", ["COVERED_BY access_control[allow_if: is_granted('ROLE_A'),ips: 10.0.0.0/8]", "COVERED_BY access_control[allow_if: is_granted('ROLE_A'),ips: 10.0.0.0/8]", "COVERED_BY access_control[allow_if: is_granted('ROLE_A'),ips: 10.0.0.0/8]"]];
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_the_rules_of_every_configuration_file_are_walked_in_the_order_the_application_loads_them(): void
    {
        $lacks = 'LACKS_ACCESS_CHECK';

        self::assertSame([self::USERS.$lacks, self::EXPORT.$lacks, self::AB.$lacks], $this->routeLines("        - { path: ^/, requires_channel: https }\n", [
            'config/packages/prod/security.yaml' => "security:\n    access_control:\n        - { path: ^/admin, roles: ROLE_ADMIN }\n",
        ]));
    }

    /**
     * @param array{0: string, 1: string, 2: string} $labels
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('rulesThatAllCarryRolesCases')]
    public function test_rules_that_all_carry_roles_or_an_expression_label_each_route_as_before(string $accessControl, array $labels): void
    {
        self::assertSame([self::USERS.$labels[0], self::EXPORT.$labels[1], self::AB.$labels[2]], $this->routeLines($accessControl));
    }

    /** @return iterable<string, array{0: string, 1: array{0: string, 1: string, 2: string}}> */
    public static function rulesThatAllCarryRolesCases(): iterable
    {
        $same = static fn (string $label): array => [$label, $label, $label];

        yield 'one rule' => ["        - { path: ^/admin, roles: ROLE_ADMIN }\n", $same('COVERED_BY access_control[ROLE_ADMIN]')];
        yield 'one rule with a channel and ips' => ["        - { path: ^/admin, roles: ROLE_ADMIN, requires_channel: https, ips: [10.0.0.0/8] }\n", $same('COVERED_BY access_control[ROLE_ADMIN,ips: 10.0.0.0/8,requires_channel: https]')];
        yield 'a POST rule before a broader rule' => ["        - { path: ^/admin, roles: ROLE_ADMIN, methods: [POST] }\n        - { path: ^/, roles: ROLE_USER }\n", $same('COVERED_BY access_control[ROLE_USER]')];
        yield 'rules of one path around a rule of a narrower path' => ["        - { path: ^/admin, roles: ROLE_X, methods: [POST] }\n        - { path: ^/admin/a, roles: ROLE_Y }\n        - { path: ^/admin, roles: ROLE_Z }\n", $same('COVERED_BY access_control[ROLE_X,methods: POST,or: ROLE_Z]')];
        yield 'a route name rule with an expression before a path rule' => ["        - { route: admin_users, allow_if: \"is_granted('ROLE_A')\" }\n        - { path: ^/admin, roles: [ROLE_B, ROLE_C] }\n", ["COVERED_BY access_control[allow_if: is_granted('ROLE_A')]", 'COVERED_BY access_control[ROLE_B,ROLE_C]', 'COVERED_BY access_control[ROLE_B,ROLE_C]']];
        yield 'a public rule before a broader rule' => ["        - { path: ^/admin/export, roles: PUBLIC_ACCESS }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n", ['COVERED_BY access_control[ROLE_ADMIN]', 'LACKS_ACCESS_CHECK', 'COVERED_BY access_control[ROLE_ADMIN]']];
        yield 'a GET rule before a rule of the same path' => ["        - { path: ^/admin, roles: ROLE_READ, methods: [GET] }\n        - { path: ^/admin, roles: ROLE_WRITE }\n", $same('COVERED_BY access_control[ROLE_READ,methods: GET,or: ROLE_WRITE]')];
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_the_declared_rules_of_two_applications_the_run_is_narrowed_to_and_of_the_project_never_mix(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingOf([
            'config/packages/security.yaml' => "security:\n    access_control:\n        - { path: ^/ }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n",
            'apps/api/config/packages/security.yaml' => "security:\n    access_control:\n        - { path: ^/, requires_channel: https }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n",
            'apps/admin/config/packages/security.yaml' => "security:\n    access_control:\n        - { path: ^/admin, roles: ROLE_ADMIN }\n        - { path: ^/, requires_channel: https }\n",
            'src/Controller/AdminController.php' => self::ADMIN_CONTROLLER,
            'apps/api/src/Controller/AdminController.php' => self::ADMIN_CONTROLLER,
            'apps/admin/src/Controller/AdminController.php' => self::ADMIN_CONTROLLER,
        ], ['apps/api', 'apps/admin']));

        self::assertStringContainsString('- GET /admin/users — src/Controller/AdminController.php::users — LACKS_ACCESS_CHECK', $rendered);
        self::assertStringContainsString('- GET /admin/users — apps/api/src/Controller/AdminController.php::users — LACKS_ACCESS_CHECK', $rendered);
        self::assertStringContainsString('- GET /admin/users — apps/admin/src/Controller/AdminController.php::users — COVERED_BY access_control[ROLE_ADMIN]', $rendered);
    }

    /**
     * @param array<string, string> $otherConfigurationFiles
     *
     * @return list<string>
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private function routeLines(string $accessControl, array $otherConfigurationFiles = []): array
    {
        $projectFiles = [
            ProjectFile::create('src/Controller/AdminController.php', '/app/src/Controller/AdminController.php', self::ADMIN_CONTROLLER),
            ProjectFile::create('config/packages/security.yaml', '/app/config/packages/security.yaml', "security:\n    access_control:\n".$accessControl),
        ];
        foreach ($otherConfigurationFiles as $relativePath => $content) {
            $projectFiles[] = ProjectFile::create($relativePath, '/app/'.$relativePath, $content);
        }

        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->setProjectFiles($projectFiles);

        (new MappingStage(new NullLogger(), new PhpParserControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser()))->process($auditContext);

        $symfonyMapping = $auditContext->mapping();
        self::assertInstanceOf(SymfonyMapping::class, $symfonyMapping);

        return array_values(array_filter(
            explode("\n", SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping)),
            static fn (string $line): bool => str_starts_with($line, '- '),
        ));
    }

    /**
     * @param array<string, string> $files
     * @param list<string>          $scanPaths
     *
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private function mappingOf(array $files, array $scanPaths): SymfonyMapping
    {
        $projectFiles = [];
        foreach ($files as $relativePath => $content) {
            $projectFiles[] = ProjectFile::create($relativePath, '/app/'.$relativePath, $content);
        }

        $auditContext = AuditContext::forProject(sys_get_temp_dir(), $scanPaths);
        $auditContext->setProjectFiles($projectFiles);

        (new MappingStage(new NullLogger(), new PhpParserControllerAccessControlParser(), new NullVoterCapabilityParser(), new NullFormBindingParser(), new SymfonyYamlSecurityConfigParser()))->process($auditContext);

        $symfonyMapping = $auditContext->mapping();
        self::assertInstanceOf(SymfonyMapping::class, $symfonyMapping);

        return $symfonyMapping;
    }
}
