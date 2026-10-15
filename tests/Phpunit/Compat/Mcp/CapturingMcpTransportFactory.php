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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Mcp;

use Mcp\Server\Transport\TransportInterface;
use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpTransportFactoryInterface;

/**
 * Hands `mcp:serve` a client that initializes a session and lists the tools,
 * the requests every MCP client makes before it calls one.
 */
final readonly class CapturingMcpTransportFactory implements McpTransportFactoryInterface
{
    private const array MESSAGES = [
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"compat","version":"1.0.0"}}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
    ];

    public function __construct(
        private string $output,
    ) {}

    /**
     * @return TransportInterface<mixed>
     */
    #[Override]
    public function create(): TransportInterface
    {
        return new CapturingMcpTransport(self::MESSAGES, $this->output);
    }
}
