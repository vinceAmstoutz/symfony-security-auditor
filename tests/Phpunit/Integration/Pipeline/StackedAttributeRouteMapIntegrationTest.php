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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\SymfonyMappingContextRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;

final class StackedAttributeRouteMapIntegrationTest extends TestCase
{
    /**
     * @throws InvalidProjectFileException
     */
    public function test_every_route_of_an_action_with_stacked_guards_and_routes_stays_within_the_documented_bound(): void
    {
        $routeMap = $this->routeMapOfAnActionStacking(1000, array_map(static fn (int $index): string => '/a'.$index, range(0, 999)));

        $routeLines = $this->routeLines($routeMap);

        self::assertCount(1000, $routeLines);
        self::assertLessThan(200, max(array_map(strlen(...), $routeLines)));
        self::assertLessThan(200_000, \strlen($routeMap));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_route_stacked_thousands_of_times_is_listed_once(): void
    {
        $routeMap = $this->routeMapOfAnActionStacking(1000, array_fill(0, 1000, '/same'));

        self::assertSame(
            ['- ANY /same — src/Controller/StackedController.php::stacked — method:#[IsGranted('.implode(',', array_map(static fn (int $index): string => 'ROLE_'.$index, range(0, 9))).',… and 990 more)]'],
            $this->routeLines($routeMap),
        );
    }

    /**
     * @param list<string> $routePaths
     *
     * @throws InvalidProjectFileException
     */
    private function routeMapOfAnActionStacking(int $guardCount, array $routePaths): string
    {
        $attributes = '';
        for ($i = 0; $i < $guardCount; ++$i) {
            $attributes .= \sprintf("#[IsGranted('ROLE_%d')]\n", $i);
        }

        foreach ($routePaths as $routePath) {
            $attributes .= \sprintf("#[Route('%s')]\n", $routePath);
        }

        $source = <<<PHP
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            final class StackedController extends AbstractController {
            {$attributes}public function stacked(): void {}
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/StackedController.php', '/app/src/Controller/StackedController.php', $source);

        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups(['controllers' => [$projectFile]]),
            new AccessControlMap(routeAccessControls: (new PhpParserControllerAccessControlParser())->parse($projectFile)),
        );

        return SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping);
    }

    /**
     * @return list<string>
     */
    private function routeLines(string $routeMap): array
    {
        return array_values(array_filter(explode("\n", $routeMap), static fn (string $line): bool => str_starts_with($line, '- ')));
    }
}
