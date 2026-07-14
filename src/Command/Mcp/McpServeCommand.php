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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;

/** @internal not part of the BC promise — the command *name* (`mcp:serve`) is public, but the PHP class itself is for internal use only. */
#[AsCommand(name: self::NAME, description: self::DESCRIPTION)]
final readonly class McpServeCommand
{
    public const string NAME = 'mcp:serve';

    public const string DESCRIPTION = 'Start a Model Context Protocol (MCP) server over stdio exposing the auditor as tools';

    public function __construct(
        private McpServerFactoryInterface $mcpServerFactory,
        private McpTransportFactoryInterface $mcpTransportFactory,
    ) {}

    public function __invoke(): int
    {
        $this->mcpServerFactory->create()->run($this->mcpTransportFactory->create());

        return Command::SUCCESS;
    }
}
