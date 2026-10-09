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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\UnmatchedClosers;

final class UnmatchedClosersTest extends TestCase
{
    #[DataProvider('sourceCases')]
    public function test_it_tells_whether_a_source_holds_more_unmatched_closers_than_the_limit(string $source, bool $exceedsLimit): void
    {
        self::assertSame($exceedsLimit, UnmatchedClosers::exceedLimit($source));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function sourceCases(): iterable
    {
        yield 'an empty source' => ['', false];
        yield 'parentheses closed as often as they are opened' => [str_repeat('(', 3000).str_repeat(')', 3000), false];
        yield 'siblings of every kind' => [str_repeat('()', 3000).str_repeat('[]', 3000).str_repeat('{}', 3000), false];
        yield 'parentheses left open' => [str_repeat('(', 5000), false];
        yield 'as many unmatched parentheses as the limit' => [str_repeat(')', 1000), false];
        yield 'one unmatched parenthesis past the limit' => [str_repeat(')', 1001), true];
        yield 'as many unmatched square brackets as the limit' => [str_repeat(']', 1000), false];
        yield 'one unmatched square bracket past the limit' => [str_repeat(']', 1001), true];
        yield 'as many unmatched curly braces as the limit' => [str_repeat('}', 1000), false];
        yield 'one unmatched curly brace past the limit' => [str_repeat('}', 1001), true];
        yield 'openers of the same kind taken off the closers' => [str_repeat(')', 1500).str_repeat('(', 500), false];
        yield 'one closer more once the openers are taken off' => [str_repeat(')', 1501).str_repeat('(', 500), true];
        yield 'unmatched closers of every kind added up to the limit' => [str_repeat(')', 400).str_repeat(']', 300).str_repeat('}', 300), false];
        yield 'unmatched closers of every kind added up past the limit' => [str_repeat(')', 400).str_repeat(']', 300).str_repeat('}', 301), true];
        yield 'openers of another kind taken off nothing' => [str_repeat('(', 500).str_repeat(']', 1001), true];
        yield 'surplus openers of one kind and closers of another' => [str_repeat('{', 2000).str_repeat(')', 1000), false];
    }
}
