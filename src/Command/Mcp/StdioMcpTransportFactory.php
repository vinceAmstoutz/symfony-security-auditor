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

use Mcp\Server\Transport\StdioTransport;
use Mcp\Server\Transport\TransportInterface;
use Override;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class StdioMcpTransportFactory implements McpTransportFactoryInterface
{
    /**
     * @return TransportInterface<mixed>
     */
    #[Override]
    public function create(): TransportInterface
    {
        return new StdioTransport();
    }
}
