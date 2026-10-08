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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Input\ArrayInput;
use VinceAmstoutz\SymfonySecurityAuditor\Command\GivenFormatOption;

final class GivenFormatOptionTest extends TestCase
{
    /**
     * @param list<string> $tokens
     */
    #[DataProvider('commandLinesNamingTheFormat')]
    public function test_a_command_line_naming_the_format_is_recognised(array $tokens): void
    {
        self::assertTrue(GivenFormatOption::in(new ArgvInput(['bin', ...$tokens])));
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function commandLinesNamingTheFormat(): iterable
    {
        yield 'long option and a value' => [['audit', '--format', 'json']];
        yield 'long option with equals' => [['audit', '--format=json']];
        yield 'short option and a value' => [['audit', '-f', 'json']];
        yield 'short option glued to its value' => [['audit', '-fjson']];
        yield 'short option clustered after a flag' => [['audit', '-nf', 'json']];
        yield 'short option clustered after several flags' => [['audit', '-vqf', 'json']];
        yield 'short option clustered after the verbose flag' => [['audit', '-Vhf', 'json']];
    }

    /**
     * @param list<string> $tokens
     */
    #[DataProvider('commandLinesNotNamingTheFormat')]
    public function test_a_command_line_not_naming_the_format_is_not_taken_for_one(array $tokens): void
    {
        self::assertFalse(GivenFormatOption::in(new ArgvInput(['bin', ...$tokens])));
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function commandLinesNotNamingTheFormat(): iterable
    {
        yield 'no option' => [['audit']];
        yield 'flags only' => [['audit', '-nq']];
        yield 'an output file whose name starts with f' => [['audit', '-ofile.txt']];
        yield 'an output file clustered after a flag' => [['audit', '-nof.txt']];
        yield 'a path whose value starts with f' => [['audit', '-pf']];
        yield 'another long option' => [['audit', '--no-output']];
        yield 'a project argument' => [['audit', 'format']];
        yield 'after the options terminator' => [['audit', '--', '-nf']];
    }

    public function test_an_array_input_naming_the_format_is_recognised(): void
    {
        self::assertTrue(GivenFormatOption::in(new ArrayInput(['--format' => 'json'])));
    }

    public function test_an_array_input_without_the_format_is_not(): void
    {
        self::assertFalse(GivenFormatOption::in(new ArrayInput(['--output' => 'a.json'])));
    }
}
