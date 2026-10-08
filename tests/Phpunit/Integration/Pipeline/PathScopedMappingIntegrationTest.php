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
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\MappingStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\ProjectFileScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\SymfonyMappingContextRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserVoterCapabilityParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

final class PathScopedMappingIntegrationTest extends TestCase
{
    private string $tmpDir;

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_route_covered_by_access_control_is_not_reported_as_lacking_a_check_when_a_path_narrows_the_run(): void
    {
        $this->writeProject('');

        $routeMap = $this->routeAccessControlMap(['src/Controller']);

        self::assertStringContainsString('GET /admin/users — src/Controller/AdminController.php::list — COVERED_BY access_control[ROLE_ADMIN]', $routeMap);
        self::assertStringNotContainsString('LACKS_ACCESS_CHECK', $routeMap);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_path_to_a_folder_outside_the_configured_scope_still_maps_the_routes_it_holds(): void
    {
        $this->writeProject('apps/api/');

        self::assertStringContainsString(
            'GET /admin/users — apps/api/src/Controller/AdminController.php::list',
            $this->routeAccessControlMap(['apps/api']),
        );
    }

    /**
     * @param list<string> $scanPaths
     *
     * @throws InvalidAuditContextException
     */
    private function routeAccessControlMap(array $scanPaths): string
    {
        $auditContext = AuditContext::forProject($this->tmpDir, $scanPaths);
        (new IngestionStage(new ProjectFileScanner(new NullLogger()), new NullLogger()))->process($auditContext);
        (new MappingStage(new NullLogger(), new PhpParserControllerAccessControlParser(), new PhpParserVoterCapabilityParser(), new PhpParserFormBindingParser(), new SymfonyYamlSecurityConfigParser(new NullLogger())))->process($auditContext);

        $symfonyMapping = $auditContext->mapping();
        self::assertInstanceOf(SymfonyMapping::class, $symfonyMapping);

        return SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping);
    }

    private function writeProject(string $root): void
    {
        $filesystem = new Filesystem();
        $filesystem->dumpFile($this->tmpDir.'/'.$root.'config/packages/security.yaml', <<<'YAML'
            security:
                firewalls:
                    main:
                        lazy: true
                access_control:
                    - { path: ^/admin, roles: ROLE_ADMIN }
            YAML);
        $filesystem->dumpFile($this->tmpDir.'/'.$root.'src/Controller/AdminController.php', <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            use Symfony\Component\HttpFoundation\Response;
            use Symfony\Component\Routing\Attribute\Route;
            class AdminController extends AbstractController
            {
                #[Route('/admin/users', methods: ['GET'])]
                public function list(): Response { return new Response('x'); }
            }
            PHP);
    }

    #[Override]
    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/path_scoped_mapping_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmpDir);
    }
}
