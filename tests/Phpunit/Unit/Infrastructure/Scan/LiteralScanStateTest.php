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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\LiteralScanState;

final class LiteralScanStateTest extends TestCase
{
    /**
     * @param array<string, int> $expected
     */
    #[DataProvider('closingLimitCases')]
    public function test_it_finds_the_last_unescaped_quote_of_each_kind(string $line, array $expected): void
    {
        self::assertSame($expected, LiteralScanState::closingLimits($line));
    }

    /** @return iterable<string, array{0: string, 1: array<string, int>}> */
    public static function closingLimitCases(): iterable
    {
        $none = \PHP_INT_MIN;

        yield 'an empty line' => ['', ["'" => $none, '"' => $none]];
        yield 'a line without a quote' => ['foo(bar)', ["'" => $none, '"' => $none]];
        yield 'a quote at the start' => ["'", ["'" => 0, '"' => $none]];
        yield 'a quote at the end' => ['abc"', ["'" => $none, '"' => 3]];
        yield 'the last of several quotes' => ["a'b'c'd", ["'" => 5, '"' => $none]];
        yield 'a quote of each kind' => ["'a\"", ["'" => 0, '"' => 2]];
        yield 'an escaped quote' => ["'a\\'", ["'" => 0, '"' => $none]];
        yield 'a quote after an escaped backslash' => ["'a\\\\'", ["'" => 4, '"' => $none]];
        yield 'a quote after three backslashes' => ["'a\\\\\\'", ["'" => 0, '"' => $none]];
        yield 'a quote after four backslashes' => ["'a\\\\\\\\'", ["'" => 6, '"' => $none]];
        yield 'an unescaped quote before an escaped one' => ["'a'b\\'", ["'" => 2, '"' => $none]];
        yield 'an escaped quote of one kind beside an unescaped one of the other' => ["\\\"a'", ["'" => 3, '"' => $none]];
        yield 'a backslash that is not before a quote' => ["a\\b'", ["'" => 3, '"' => $none]];
        yield 'a backslash run broken by another character' => ["\\\\a\\'", ["'" => $none, '"' => $none]];
    }
}
