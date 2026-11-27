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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Command;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\StreamOutput;
use VinceAmstoutz\SymfonySecurityAuditor\Command\CommandOutputHolder;

final class CommandOutputHolderTest extends TestCase
{
    public function test_a_command_that_prints_to_a_terminal_stream_prints_to_a_terminal(): void
    {
        $terminal = fopen('/dev/ptmx', 'r+');
        self::assertIsResource($terminal);
        $commandOutputHolder = new CommandOutputHolder();

        $commandOutputHolder->set(new StreamOutput($terminal));

        self::assertTrue($commandOutputHolder->isTerminal());
    }

    public function test_a_command_that_prints_to_a_stream_nobody_reads_live_prints_to_no_terminal(): void
    {
        $pipe = fopen('php://memory', 'w+');
        self::assertIsResource($pipe);
        $commandOutputHolder = new CommandOutputHolder();

        $commandOutputHolder->set(new StreamOutput($pipe));

        self::assertFalse($commandOutputHolder->isTerminal());
    }

    public function test_a_command_that_prints_to_the_buffer_of_its_caller_prints_to_no_terminal(): void
    {
        $commandOutputHolder = new CommandOutputHolder();

        $commandOutputHolder->set(new BufferedOutput());

        self::assertFalse($commandOutputHolder->isTerminal());
    }

    public function test_no_command_running_prints_to_no_terminal(): void
    {
        self::assertFalse((new CommandOutputHolder())->isTerminal());
    }
}
