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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Port;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BalancedBlockScanner;

final class BalancedBlockScannerTest extends TestCase
{
    /** @param list<int> $expectedPositions */
    #[DataProvider('openerCases')]
    public function test_it_lists_the_openers_outside_string_literals(string $content, array $expectedPositions): void
    {
        self::assertSame($expectedPositions, BalancedBlockScanner::openerPositions($content));
    }

    /** @return iterable<string, array{string, list<int>}> */
    public static function openerCases(): iterable
    {
        yield 'brackets and braces in order' => ['a [b] {c}', [2, 6]];
        yield 'a bracket held by a string literal is skipped' => ['"[x]" [y]', [6]];
        yield 'an escaped quote does not close its string' => ['"a\\"[" [y]', [7]];
        yield 'every opener counts once a stray quote leaves the quotes unpaired' => ['5" [y]', [3]];
        yield 'no opener' => ['plain text', []];
    }

    #[DataProvider('blockCases')]
    public function test_it_reads_the_block_an_opener_starts(string $content, int $start, ?string $expectedBlock): void
    {
        self::assertSame($expectedBlock, BalancedBlockScanner::balancedBlockOpenedAt($content, $start));
    }

    /** @return iterable<string, array{string, int, string|null}> */
    public static function blockCases(): iterable
    {
        yield 'nested brackets' => ['x [1, [2]] y', 2, '[1, [2]]'];
        yield 'braces' => ['x {"a": {"b": 1}} y', 2, '{"a": {"b": 1}}'];
        yield 'a closer inside a string literal does not end the block' => ['{"a": "}"} tail', 0, '{"a": "}"}'];
        yield 'a block that never closes' => ['[1, [2]', 0, null];
    }

    #[DataProvider('singleBlockCases')]
    public function test_it_tells_whether_the_content_is_one_block(string $content, bool $expected): void
    {
        self::assertSame($expected, BalancedBlockScanner::contentIsSingleBalancedBlock($content));
    }

    /** @return iterable<string, array{string, bool}> */
    public static function singleBlockCases(): iterable
    {
        yield 'a list' => ['[1]', true];
        yield 'an object' => ['{"a": 1}', true];
        yield 'a block followed by prose' => ['[1] and more', false];
        yield 'prose before a block' => ['see [1]', false];
        yield 'an unclosed block' => ['[1', false];
        yield 'empty content' => ['', false];
    }
}
