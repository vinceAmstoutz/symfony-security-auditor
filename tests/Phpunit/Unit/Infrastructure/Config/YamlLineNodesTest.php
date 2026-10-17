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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\YamlLineNodes;

final class YamlLineNodesTest extends TestCase
{
    /**
     * @param list<int> $expected
     */
    #[DataProvider('lines')]
    public function test_it_finds_where_the_nodes_a_line_opens_begin(string $line, array $expected): void
    {
        self::assertSame($expected, YamlLineNodes::columnsOf($line, 32));
    }

    /**
     * @return iterable<string, array{string, list<int>}>
     */
    public static function lines(): iterable
    {
        yield 'an empty line' => ['', []];
        yield 'a line of spaces' => ['    ', []];
        yield 'a line of blanks' => [" \t ", []];
        yield 'a comment' => ['  # key: - value', []];
        yield 'a key and its value' => ['key: value', [0]];
        yield 'an indented key opening a block' => ['  key:', [2]];
        yield 'a sequence item' => ['- item', [0]];
        yield 'a marker alone' => ['-', [0]];
        yield 'compact block sequences' => ['  - - item', [2, 4]];
        yield 'a compact mapping inside a sequence' => ['- key: value', [0, 2]];
        yield 'markers separated by tabs' => ["-\t-\titem", [0, 2]];
        yield 'markers run together' => ['- --item', [0, 2, 3]];
        yield 'complex-key markers' => ['? ? key', [0, 2]];
        yield 'a marker followed by no blank' => ['- -1', [0, 2]];
        yield 'anchors and tags before a marker' => ['- &node !!seq - item', [0, 14]];
        yield 'a property ending the line' => ['- &node', [0]];
        yield 'a property opening the line' => ['&node - item', [0, 6]];
        yield 'a quoted key' => ['"key": - item', [0, 7]];
        yield 'blanks before the colon of a key' => ['key  : - item', [0, 7]];
        yield 'a colon inside a key' => ['k:e: - item', [0, 5]];
        yield 'a colon inside a URL value' => ['base_url: http://localhost:11434', [0]];
        yield 'a flow sequence' => ['key: [a: b]', [0]];
        yield 'a flow mapping' => ['key: {a: b}', [0]];
        yield 'a flow sequence of mappings' => ['key: [{a: b}]', [0]];
        yield 'a comment after a key' => ['key: # a: b', [0]];
        yield 'a merge key holding a sequence' => ['<<: - <<: - item', [0, 4, 6, 10]];
    }

    public function test_it_reads_no_further_than_the_nodes_worth_finding(): void
    {
        self::assertSame([0, 2, 4], YamlLineNodes::columnsOf('- - - - item', 2));
    }

    public function test_it_reads_as_many_nodes_as_are_worth_finding(): void
    {
        self::assertSame([0, 2, 4, 6], YamlLineNodes::columnsOf('- - - - item', 3));
    }
}
