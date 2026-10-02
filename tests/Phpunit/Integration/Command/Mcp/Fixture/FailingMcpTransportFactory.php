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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Mcp\Fixture;

use Mcp\Server\Transport\TransportInterface;
use Override;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpTransportFactoryInterface;

final readonly class FailingMcpTransportFactory implements McpTransportFactoryInterface
{
    public const string FAILURE = 'The stdio transport could not be opened.';

    /**
     * @return TransportInterface<mixed>
     */
    #[Override]
    public function create(): TransportInterface
    {
        throw new RuntimeException(self::FAILURE);
    }
}
