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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlNesting;

final class YamlNestingTest extends TestCase
{
    #[DataProvider('files')]
    public function test_it_counts_the_levels_open_at_once_and_each_line_once_per_level_open_around_it(string $yaml, int $depth, int $nestedBytes): void
    {
        $yamlNesting = YamlNesting::of($yaml, 32);

        self::assertSame($depth, $yamlNesting->depth);
        self::assertSame($nestedBytes, $yamlNesting->nestedBytes);
    }

    /**
     * @return iterable<string, array{string, int, int}>
     */
    public static function files(): iterable
    {
        yield 'an empty file' => ['', 0, 0];
        yield 'a top-level comment' => ['# note', 0, 0];
        yield 'one key, its line break counted' => ["a: 1\n", 1, 6];
        yield 'two sibling keys' => ["a: 1\nb: 1\n", 1, 11];
        yield 'a nested key' => ["a:\n  b: 1\n", 2, 19];
        yield 'a comment inside a block, counted at the levels open around it' => ["a:\n# x\n  b: 1", 2, 21];
        yield 'a blank line inside a block' => ["a:\n\n  b: 1", 2, 18];
        yield 'a line closing the levels deeper than it' => ["a:\n  b:\nc: 1", 2, 18];
        yield 'compact block sequences' => ['- - x', 2, 12];
        yield 'compact levels kept open for the lines nested under them' => ["- - a:\n      b: 1", 4, 65];
        yield 'Windows line endings, each break counted once' => ["a:\r\n  b: 1\r\n", 2, 19];
        yield 'carriage returns alone, which end a line as a line feed does' => ["-\r -\r  - x", 3, 26];
    }

    public function test_it_stops_reading_a_file_once_it_nests_past_the_limit(): void
    {
        $yamlNesting = YamlNesting::of("a: 1\n- - - x\n- y", 2);

        self::assertSame(3, $yamlNesting->depth);
        self::assertSame(5, $yamlNesting->nestedBytes);
    }

    public function test_it_reads_a_file_nesting_to_the_limit_whole(): void
    {
        $yamlNesting = YamlNesting::of("- - x\n- y", 2);

        self::assertSame(2, $yamlNesting->depth);
        self::assertSame(16, $yamlNesting->nestedBytes);
    }
}
