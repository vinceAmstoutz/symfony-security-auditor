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
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\StandardInput;

final class StandardInputTest extends TestCase
{
    public function test_an_input_that_reads_a_terminal_is_answered_at_a_terminal(): void
    {
        $terminal = fopen('/dev/ptmx', 'r+');
        self::assertIsResource($terminal);
        $arrayInput = new ArrayInput([]);
        $arrayInput->setStream($terminal);

        self::assertTrue((new StandardInput())->isTerminal($arrayInput));
    }

    public function test_an_input_that_reads_a_stream_of_prepared_answers_is_not_answered_at_a_terminal(): void
    {
        $answers = fopen('php://memory', 'r+');
        self::assertIsResource($answers);
        $arrayInput = new ArrayInput([]);
        $arrayInput->setStream($answers);

        self::assertFalse((new StandardInput())->isTerminal($arrayInput));
    }

    public function test_an_input_with_no_stream_of_its_own_reads_the_standard_input(): void
    {
        self::assertSame(stream_isatty(\STDIN), (new StandardInput())->isTerminal(new ArrayInput([])));
    }

    public function test_an_input_that_cannot_carry_a_stream_reads_the_standard_input(): void
    {
        self::assertSame(stream_isatty(\STDIN), (new StandardInput())->isTerminal(self::createStub(InputInterface::class)));
    }
}
