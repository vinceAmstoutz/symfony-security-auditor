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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command\Mcp;

use Mcp\Server\Transport\StdioTransport;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\StdioMcpTransportFactory;

final class StdioMcpTransportFactoryTest extends TestCase
{
    public function test_it_creates_a_stdio_transport(): void
    {
        self::assertInstanceOf(StdioTransport::class, (new StdioMcpTransportFactory())->create());
    }
}
