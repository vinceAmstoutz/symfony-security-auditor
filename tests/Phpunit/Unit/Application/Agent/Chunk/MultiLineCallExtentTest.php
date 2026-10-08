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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\MultiLineCallExtent;

final class MultiLineCallExtentTest extends TestCase
{
    /**
     * @param list<string> $lines
     * @param list<int>    $expectedIndexes
     */
    #[DataProvider('statementCases')]
    public function test_it_names_the_lines_a_statement_spans(array $lines, int $startIndex, array $expectedIndexes): void
    {
        self::assertSame($expectedIndexes, (new MultiLineCallExtent())->lineIndexes($lines, $startIndex));
    }

    #[DataProvider('closingLines')]
    public function test_a_call_left_open_is_followed_for_a_bounded_number_of_lines(int $closingIndex, int $expectedLineCount): void
    {
        $lines = ['call('];
        for ($index = 1; $index < $closingIndex; ++$index) {
            $lines[] = '    $argument,';
        }

        $lines[] = ');';
        $lines[] = 'INERT';

        self::assertSame(range(0, $expectedLineCount - 1), (new MultiLineCallExtent())->lineIndexes($lines, 0));
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function closingLines(): iterable
    {
        yield 'closed on the last line the lookahead covers' => [MultiLineCallExtent::MAX_LOOKAHEAD_LINES - 1, MultiLineCallExtent::MAX_LOOKAHEAD_LINES];
        yield 'closed one line past the lookahead' => [MultiLineCallExtent::MAX_LOOKAHEAD_LINES, 1];
        yield 'closed far past the lookahead' => [MultiLineCallExtent::MAX_LOOKAHEAD_LINES * 10, 1];
    }

    public function test_a_flood_of_open_calls_is_resolved_without_reading_the_rest_of_the_file_each_time(): void
    {
        $lines = [];
        for ($index = 0; $index < 4000; ++$index) {
            $lines[] = \sprintf('exec($cmd%d,', $index);
        }

        $multiLineCallExtent = new MultiLineCallExtent();
        $start = hrtime(true);
        foreach (array_keys($lines) as $startIndex) {
            $multiLineCallExtent->lineIndexes($lines, $startIndex);
        }

        self::assertLessThan(1_000_000_000, hrtime(true) - $start);
    }

    /**
     * @return iterable<string, array{list<string>, int, list<int>}>
     */
    public static function statementCases(): iterable
    {
        yield 'a call closed on its own line spans that line only' => [
            ['<?php', '$stmt = $this->pdo->query($sql);', 'INERT'],
            1,
            [1],
        ];

        yield 'a statement without parentheses spans its line only' => [
            ['<?php', '$sql = "SELECT " . $name;', 'INERT'],
            1,
            [1],
        ];

        yield 'a call left open spans every line up to its closing parenthesis' => [
            ['<?php', '$rows = $c->fetchAllAssociative(', '    "SELECT * FROM t WHERE n = \'" . $name . "\'"', ');', 'INERT'],
            1,
            [1, 2, 3],
        ];

        yield 'nested calls span up to the parenthesis closing the outermost one' => [
            ['foo(', '    bar(', '        $x', '    ),', '    $y', ');', 'INERT'],
            0,
            [0, 1, 2, 3, 4, 5],
        ];

        yield 'a call closing on the last line of the file spans up to it' => [
            ['<?php', '$pdo->query(', '    $sql);'],
            1,
            [1, 2],
        ];

        yield 'a marker on the closing line of a call spans that line only' => [
            ['foo(', '    $a', ');', 'INERT'],
            2,
            [2],
        ];

        yield 'a call never closed spans its first line only' => [
            ['<?php', '$pdo->query(', '$a = 1;', '$b = 2;'],
            1,
            [1],
        ];

        yield 'a start line beyond the file spans no line' => [
            ['<?php', '$a = 1;'],
            5,
            [],
        ];

        yield 'parentheses inside double-quoted strings are not counted' => [
            ['$pdo->query(', '    "SELECT (" . $name . ")) ("', ');', 'INERT'],
            0,
            [0, 1, 2],
        ];

        yield 'parentheses and escaped quotes inside single-quoted strings are not counted' => [
            ['$pdo->query(', '    \'it\\\'s (\' . $name', ');', 'INERT'],
            0,
            [0, 1, 2],
        ];

        yield 'a string literal spanning lines is part of the call' => [
            ['$pdo->query(', '    "SELECT *', '       FROM t', '      WHERE n = \'" . $name . "\'"', ');', 'INERT'],
            0,
            [0, 1, 2, 3, 4],
        ];

        yield 'a line comment with an apostrophe and an open parenthesis is ignored' => [
            ['$pdo->query( // the user\'s (raw) query', '    $sql', ');', 'INERT'],
            0,
            [0, 1, 2],
        ];

        yield 'a hash comment with an apostrophe and an open parenthesis is ignored' => [
            ['$pdo->query( # the user\'s (raw) query', '    $sql', ');', 'INERT'],
            0,
            [0, 1, 2],
        ];

        yield 'a block comment spanning lines is part of the call and its parentheses are ignored' => [
            ['$pdo->query(', "    /* the user's (raw)", '       query */ $sql', ');', 'INERT'],
            0,
            [0, 1, 2, 3],
        ];

        yield 'an attribute opener is not a hash comment' => [
            ['$pdo->query(', '    #[Sensitive] $sql)', 'INERT'],
            0,
            [0, 1],
        ];
    }
}
