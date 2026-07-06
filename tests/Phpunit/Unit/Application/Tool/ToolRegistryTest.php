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

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

final class ToolRegistryTest extends TestCase
{
    public function test_definitions_returns_one_entry_per_registered_tool(): void
    {
        $toolRegistry = new ToolRegistry(
            tools: [$this->makeTool('a'), $this->makeTool('b')],
            logger: new NullLogger(),
        );

        $names = array_map(static fn (ToolDefinition $toolDefinition): string => $toolDefinition->name, $toolRegistry->definitions());

        self::assertSame(['a', 'b'], $names);
    }

    public function test_has_returns_true_for_registered_tool(): void
    {
        $toolRegistry = new ToolRegistry(
            tools: [$this->makeTool('a')],
            logger: new NullLogger(),
        );

        self::assertTrue($toolRegistry->has('a'));
        self::assertFalse($toolRegistry->has('b'));
    }

    public function test_execute_dispatches_to_registered_tool(): void
    {
        $toolRegistry = new ToolRegistry(
            tools: [$this->makeTool('read_file', static function (array $args): string {
                $key = $args['key'] ?? 'none';

                return 'got '.(\is_string($key) ? $key : 'none');
            })],
            logger: new NullLogger(),
        );

        $result = $toolRegistry->execute('read_file', ['key' => 'hello']);

        self::assertSame('got hello', $result);
    }

    public function test_execute_returns_error_text_for_unknown_tool(): void
    {
        $toolRegistry = new ToolRegistry(
            tools: [],
            logger: new NullLogger(),
        );

        $result = $toolRegistry->execute('unknown', []);

        self::assertStringContainsString('Error', $result);
        self::assertStringContainsString('unknown', $result);
    }

    public function test_execute_catches_tool_exception_and_returns_error_text(): void
    {
        $toolRegistry = new ToolRegistry(
            tools: [$this->makeTool('boom', static function (): never {
                throw new RuntimeException('kaboom');
            })],
            logger: new NullLogger(),
        );

        $result = $toolRegistry->execute('boom', []);

        self::assertStringContainsString('Error', $result);
        self::assertStringContainsString('boom', $result);
        self::assertStringContainsString('kaboom', $result);
    }

    public function test_constructor_rejects_duplicate_tool_names(): void
    {
        $this->expectException(InvalidToolRegistryException::class);

        new ToolRegistry(
            tools: [$this->makeTool('a'), $this->makeTool('a')],
            logger: new NullLogger(),
        );
    }

    public function test_execute_logs_warning_with_tool_name_when_tool_unknown(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $toolRegistry = new ToolRegistry(tools: [], logger: $logger);

        $toolRegistry->execute('ghost', []);

        self::assertSame([['Tool not found, returning error to LLM', ['tool' => 'ghost']]], $warnings);
    }

    public function test_execute_logs_warning_with_tool_name_and_error_when_tool_throws(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $toolRegistry = new ToolRegistry(
            tools: [$this->makeTool('boom', static function (): never {
                throw new RuntimeException('kaboom');
            })],
            logger: $logger,
        );

        $toolRegistry->execute('boom', []);

        self::assertCount(1, $warnings);
        self::assertSame('Tool execution failed', $warnings[0][0]);
        self::assertSame('boom', $warnings[0][1]['tool']);
        self::assertSame('kaboom', $warnings[0][1]['error']);
    }

    /**
     * @param (callable(array<string, mixed>): string)|null $execute
     */
    private function makeTool(string $name, ?callable $execute = null): ToolInterface
    {
        return new class($name, $execute) implements ToolInterface {
            /**
             * @param (callable(array<string, mixed>): string)|null $execute
             */
            public function __construct(
                private readonly string $name,
                private readonly mixed $execute,
            ) {}

            #[Override]
            public function definition(): ToolDefinition
            {
                return new ToolDefinition($this->name, 'desc-'.$this->name, ['type' => 'object']);
            }

            #[Override]
            public function execute(array $arguments): string
            {
                if (null === $this->execute) {
                    return 'ok';
                }

                return ($this->execute)($arguments);
            }
        };
    }
}
