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

    /**
     * STDOUT is the JSON-RPC channel the client parses, and the CLI SAPI
     * displays notices and warnings there by default: one stray notice would
     * corrupt the protocol stream, so PHP's error display goes to STDERR while
     * the server runs.
     */
    public function __invoke(): int
    {
        $displayErrors = ini_set('display_errors', 'stderr');

        try {
            $this->mcpServerFactory->create()->run($this->mcpTransportFactory->create());
        } finally {
            ini_set('display_errors', $displayErrors);
        }

        return Command::SUCCESS;
    }
}
