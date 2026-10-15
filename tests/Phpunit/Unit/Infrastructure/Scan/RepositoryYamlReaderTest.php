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
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Tag\TaggedValue;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\UnreadableYamlException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RepositoryYamlReader;

final class RepositoryYamlReaderTest extends TestCase
{
    /**
     * @param array<mixed> $expected
     *
     * @throws UnreadableYamlException
     */
    #[DataProvider('readableDocumentCases')]
    public function test_it_reads_a_document(string $content, array $expected): void
    {
        self::assertEquals($expected, (new RepositoryYamlReader())->read($content));
    }

    /** @return iterable<string, array{0: string, 1: array<mixed>}> */
    public static function readableDocumentCases(): iterable
    {
        yield 'a map' => ["security:\n    firewalls: ~\n", ['security' => ['firewalls' => null]]];
        yield 'an empty document' => ['', []];
        yield 'a scalar document' => ['just text', []];
        yield 'a list document' => ["- a\n- b\n", ['a', 'b']];
        yield 'forty keys of growing length at one level' => [implode('', array_map(static fn (int $length): string => \sprintf("%s: v\n", str_repeat('k', $length)), range(1, 40))), array_fill_keys(array_map(static fn (int $length): string => str_repeat('k', $length), range(1, 40)), 'v')];
        yield 'thirty-two nested levels' => [self::nestedDocument(32), self::nestedValue(32)];
        yield 'thirty-two nested levels with a deeper blank line' => [self::nestedDocument(32, str_repeat(' ', 80)."\t\n"), self::nestedValue(32)];
        yield 'thirty-two nested levels with a deeper comment' => [self::nestedDocument(32, str_repeat(' ', 80)."# a comment\n"), self::nestedValue(32)];
        yield 'a custom tag' => ["a: !tagged_iterator app.handler\n", ['a' => new TaggedValue('tagged_iterator', 'app.handler')]];
        yield 'two-space indentation' => ["a:\n  b:\n    c: 1\n", ['a' => ['b' => ['c' => 1]]]];
    }

    /**
     * @throws UnreadableYamlException
     */
    public function test_it_refuses_a_document_nested_deeper_than_thirty_two_levels(): void
    {
        $this->expectException(UnreadableYamlException::class);
        $this->expectExceptionMessage('it is nested more than the 32 levels deep the audit reads');

        (new RepositoryYamlReader())->read("# a header\n\n".self::nestedDocument(33, "z: 1\n"));
    }

    /**
     * @throws UnreadableYamlException
     */
    public function test_it_counts_the_blocks_left_open_after_a_line_closes_some(): void
    {
        $document = '';
        foreach (range(0, 19) as $indent) {
            $document .= str_repeat(' ', $indent).\sprintf("a%d:\n", $indent);
        }

        foreach (range(10, 31) as $indent) {
            $document .= str_repeat(' ', $indent).\sprintf("b%d:\n", $indent);
        }

        $this->expectException(UnreadableYamlException::class);
        $this->expectExceptionMessage('it is nested more than the 32 levels deep the audit reads');

        (new RepositoryYamlReader())->read($document.str_repeat(' ', 32)."leaf: 1\n");
    }

    /**
     * @throws UnreadableYamlException
     */
    public function test_it_reads_a_document_of_256_kib(): void
    {
        $content = "a: 1\n#".str_repeat('x', 262_144 - 7)."\n";

        self::assertSame(['a' => 1], (new RepositoryYamlReader())->read($content));
    }

    /**
     * @throws UnreadableYamlException
     */
    public function test_it_refuses_a_document_larger_than_256_kib(): void
    {
        $this->expectException(UnreadableYamlException::class);
        $this->expectExceptionMessage('it holds 262145 bytes, more than the 262144 the audit reads');

        (new RepositoryYamlReader())->read("a: 1\n#".str_repeat('x', 262_144 - 6)."\n");
    }

    public function test_it_refuses_a_document_it_cannot_parse(): void
    {
        try {
            (new RepositoryYamlReader())->read("\t{ not: yaml");
            self::fail('An unparseable document was read.');
        } catch (UnreadableYamlException $unreadableYamlException) {
            self::assertStringStartsWith('it is not valid YAML: ', $unreadableYamlException->getMessage());
            self::assertInstanceOf(ParseException::class, $unreadableYamlException->getPrevious());
        }
    }

    private static function nestedDocument(int $levels, string $tail = ''): string
    {
        $document = '';
        foreach (range(0, $levels - 2) as $level) {
            $document .= str_repeat(' ', $level).\sprintf("l%d:\n", $level);
        }

        return $document.str_repeat(' ', $levels - 1)."leaf: 1\n".$tail;
    }

    /**
     * @return array<string, mixed>
     */
    private static function nestedValue(int $levels): array
    {
        $value = ['leaf' => 1];
        foreach (range($levels - 2, 0) as $level) {
            $value = [\sprintf('l%d', $level) => $value];
        }

        return $value;
    }
}
