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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpTransportFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Mcp\CapturingMcpTransportFactory;

/**
 * `mcp:serve` as an MCP client sees it before calling anything: the answer to
 * `initialize`, and the tools `tools/list` names with their input schemas.
 */
final readonly class McpScenarios
{
    private const string RESPONSES = 'mcp-responses.json';

    /**
     * @return list<Scenario>
     */
    public static function all(): array
    {
        return [
            Scenario::bundle('mcp/tools-list')
                ->withProjectFiles(ProjectFixtures::clean())
                ->withEnvironment(['COMPAT_MCP_RESPONSES' => \sprintf('{workspace}/%s', self::RESPONSES)])
                ->withServices(static function (ContainerBuilder $containerBuilder): void {
                    $containerBuilder->register(McpTransportFactoryInterface::class, CapturingMcpTransportFactory::class)
                        ->setArguments(['%env(COMPAT_MCP_RESPONSES)%']);
                })
                ->running(new Step('mcp:serve'))
                ->collecting(self::RESPONSES),
        ];
    }
}
