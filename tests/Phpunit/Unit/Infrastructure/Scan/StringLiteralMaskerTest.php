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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\StringLiteralMasker;

final class StringLiteralMaskerTest extends TestCase
{
    #[DataProvider('literalCases')]
    public function test_it_masks_and_strips_string_literals(string $line, string $masked, string $stripped): void
    {
        $stringLiteralMasker = new StringLiteralMasker();

        self::assertSame($masked, $stringLiteralMasker->mask($line));
        self::assertSame($stripped, $stringLiteralMasker->strip($line));
    }

    /** @return iterable<string, array{0: string, 1: string, 2: string}> */
    public static function literalCases(): iterable
    {
        yield 'an empty line' => ['', '', ''];
        yield 'a line without a quote' => ['foo(bar)', 'foo(bar)', 'foo(bar)'];
        yield 'a single-quoted literal' => ["\$a = 'abc';", '$a = xxxxx;', '$a = ;'];
        yield 'a double-quoted literal' => ['"abc"', 'xxxxx', ''];
        yield 'an empty literal' => ["''", 'xx', ''];
        yield 'two empty literals of both kinds' => ["''\"\"", 'xxxx', ''];
        yield 'an empty literal followed by code' => ["'' x", 'xx x', ' x'];
        yield 'an empty literal followed by a literal' => ["'' . 'a'", 'xx . xxx', ' . '];
        yield 'an escaped quote' => ["'a\\'b'", 'xxxxxx', ''];
        yield 'an escaped backslash before the closing quote' => ["'a\\\\'", 'xxxxx', ''];
        yield 'a literal of each kind' => ["'a' . \"b\"", 'xxx . xxx', ' . '];
        yield 'a quote of the other kind inside a literal' => ["\"it's\"", 'xxxxxx', ''];
        yield 'quotes of both kinds inside literals' => ["'a\"b' \"c'd\"", 'xxxxx xxxxx', ' '];
        yield 'literals between text' => ["x 'a' y 'b' z", 'x xxx y xxx z', 'x  y  z'];
        yield 'an unterminated literal' => ["'abc", "'abc", "'abc"];
        yield 'a literal whose closing quote is escaped' => ["'a\\'", "'a\\'", "'a\\'"];
        yield 'a literal ending in a lone backslash' => ["'abc\\", "'abc\\", "'abc\\"];
        yield 'quotes that are all escaped' => ["\\'a \\'b", "\\'a \\'b", "\\'a \\'b"];
        yield 'a literal of the other kind after an unterminated one' => ["'abc \"def\"", "'abc xxxxx", "'abc "];
        yield 'a second literal of the other kind after an unterminated one' => ["'x \"y\" \"z\"", "'x xxx xxx", "'x  "];
    }

    public function test_it_reads_a_line_of_thousands_of_unterminated_quotes_in_one_pass(): void
    {
        $line = "'".str_repeat("a\\'", 20000);

        self::assertSame($line, (new StringLiteralMasker())->mask($line));
    }
}
