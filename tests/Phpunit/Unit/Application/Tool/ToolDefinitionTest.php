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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Tool;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;

final class ToolDefinitionTest extends TestCase
{
    public function test_it_exposes_name_description_and_schema(): void
    {
        $toolDefinition = new ToolDefinition('read_file', 'Reads a file', ['type' => 'object']);

        self::assertSame('read_file', $toolDefinition->name);
        self::assertSame('Reads a file', $toolDefinition->description);
        self::assertSame(['type' => 'object'], $toolDefinition->parametersSchema);
    }

    public function test_it_rejects_empty_name(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new ToolDefinition('', 'desc', []);
    }

    public function test_it_rejects_whitespace_only_name(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new ToolDefinition('  ', 'desc', []);
    }

    public function test_it_rejects_empty_description(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new ToolDefinition('read_file', '', []);
    }

    public function test_it_rejects_whitespace_only_description(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new ToolDefinition('read_file', '  ', []);
    }
}
