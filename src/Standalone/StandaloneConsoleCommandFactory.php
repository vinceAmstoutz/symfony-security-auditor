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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone;

use ReflectionClass;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Command\AuditCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpServeCommand;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnresolvableAuditCommandException;
use VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception\UnresolvableMcpServeCommandException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneConsoleCommandFactory
{
    /**
     * Describes an invokable command from its class alone — the name, aliases,
     * description and help of its `#[AsCommand]`, and the input its
     * `__invoke()` declares — for help, a listing or shell completion, none of
     * which runs it. The instance is only reflected, never invoked, so it needs
     * none of the services the container would inject.
     *
     * @param class-string<AuditCommand|McpServeCommand> $invokableClass
     */
    public function describe(string $invokableClass): Command
    {
        return new Command(null, (new ReflectionClass($invokableClass))->newInstanceWithoutConstructor());
    }

    /**
     * @throws UnresolvableAuditCommandException
     */
    public function create(ContainerBuilder $containerBuilder): Command
    {
        $auditCommand = $containerBuilder->get(AuditCommand::class);
        if (!$auditCommand instanceof AuditCommand) {
            throw UnresolvableAuditCommandException::fromContainer(AuditCommand::class);
        }

        return new Command(null, $auditCommand);
    }

    /**
     * @throws UnresolvableMcpServeCommandException
     */
    public function createMcpServer(ContainerBuilder $containerBuilder): Command
    {
        $mcpServeCommand = $containerBuilder->get(McpServeCommand::class);
        if (!$mcpServeCommand instanceof McpServeCommand) {
            throw UnresolvableMcpServeCommandException::fromContainer(McpServeCommand::class);
        }

        return new Command(null, $mcpServeCommand);
    }
}
