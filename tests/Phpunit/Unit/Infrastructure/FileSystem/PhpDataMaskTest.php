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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\FileSystem;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\PhpDataMask;

final class PhpDataMaskTest extends TestCase
{
    #[DataProvider('maskedContentCases')]
    public function test_it_tells_code_from_text_byte_by_byte(string $content, string $expectedMask): void
    {
        self::assertSame($expectedMask, (string) PhpDataMask::of($content));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function maskedContentCases(): iterable
    {
        yield 'a file with no php tag' => ['password: abc', 'ttttttttttttt'];
        yield 'a file mentioning a php tag after its first line' => ["# a\n<?php \$a = 1;", 'ttttttttttttttttt'];
        yield 'an empty file' => ['', ''];
        yield 'plain code' => ['<?php $a = 1;', 'ccccccccccccc'];
        yield 'a single-quoted string' => ["<?php \$a = 'xy';", 'ccccccccccccttec'];
        yield 'a double-quoted string without a variable' => ['<?php $a = "xy";', 'ccccccccccccttec'];
        yield 'a double-quoted string holding a variable' => ['<?php $a = "x$b y";', 'cccccccccccctccttec'];
        yield 'a string holding an expression with a string of its own' => ['<?php $a = "x{$b["k"]}y";', 'cccccccccccctccccctecctec'];
        yield 'two double-quoted strings holding a variable' => ['<?php "a$b"."c$d";', 'ccccccctccecctccec'];
        yield 'a line comment' => ["<?php // abc\n\$a;", 'ccccccttttttcccc'];
        yield 'a hash comment' => ["<?php # abc\n\$a;", 'cccccctttttcccc'];
        yield 'an attribute' => ['<?php #[Attr] $a;', 'ccccccccccccccccc'];
        yield 'a block comment' => ['<?php /* ab */ $a;', 'ccccccttttttcccccc'];
        yield 'a doc comment' => ["<?php /** ab\n */ \$a;", 'ccccccttttttttcccccc'];
        yield 'a block comment never closed' => ['<?php /* abc', 'cccccctttttt'];
        yield 'a line comment ending like a block comment' => ["<?php // a */\n", 'cccccctttttttc'];
        yield 'a comment opening and closing on its own slash' => ['<?php /*/', 'cccccctcc'];
        yield 'a heredoc' => ["<?php \$a = <<<EOT\nxy\nEOT;", 'cccccccccccccccccctttcccc'];
        yield 'a nowdoc' => ["<?php \$a = <<<'EOT'\nxy\nEOT;", 'cccccccccccccccccccctttcccc'];
        yield 'markup around the tags' => ['<?php $a; ?>abc<?= $b ?>d', 'cccccccccccctttccccccccct'];
        yield 'a heredoc holding a double quote between two interpolations' => ["<?php \$a = <<<EOT\n{\$b}\"{\$c}\nEOT;\n\$d = \"e\$f\";", 'cccccccccccccccccccccctcccctccccccccccctccec'];
        yield 'a string never closed' => ["<?php 'abc", 'cccccctttt'];
    }

    #[DataProvider('phpFileCases')]
    public function test_it_tells_a_file_opening_with_a_php_tag_from_any_other(string $content, bool $isPhp): void
    {
        self::assertSame($isPhp, PhpDataMask::opensWithPhpTag($content));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function phpFileCases(): iterable
    {
        yield 'the long tag' => ["<?php\n\$a = 1;", true];
        yield 'the long tag followed by a space' => ['<?php $a = 1;', true];
        yield 'the long tag followed by a tab' => ["<?php\t\$a = 1;", true];
        yield 'the echo tag' => ['<?= $a ?>', true];
        yield 'blank lines before the tag' => ["\n \n<?php \$a = 1;", true];
        yield 'a byte order mark before the tag' => ["\xEF\xBB\xBF<?php \$a = 1;", true];
        yield 'a shebang before the tag' => ["#!/usr/bin/env php\n<?php \$a = 1;", true];
        yield 'a byte order mark and a shebang before the tag' => ["\xEF\xBB\xBF#!/usr/bin/env php\n<?php \$a = 1;", true];
        yield 'a tag that is no php tag' => ['<?phpx $a = 1;', false];
        yield 'an xml declaration' => ['<?xml version="1.0"?>', false];
        yield 'a yaml comment mentioning the tag' => ["# <?php echo 1;\npassword: abc", false];
        yield 'markup before the tag' => ['<html><?php echo 1; ?>', false];
        yield 'text before the tag on the same line' => ['x <?php echo 1;', false];
        yield 'a shebang that is not at the start' => ["\n#!/usr/bin/env php\n<?php \$a = 1;", false];
        yield 'a shebang with the tag on the same line' => ['#!/usr/bin/env php <?php $a = 1;', false];
        yield 'an empty file' => ['', false];
    }

    public function test_it_counts_the_text_bytes_from_an_offset_within_a_length(): void
    {
        $phpDataMask = PhpDataMask::of("<?php \$a = 'abc';");

        self::assertSame(3, $phpDataMask->textLength(12, 10));
        self::assertSame(2, $phpDataMask->textLength(12, 2));
        self::assertSame(1, $phpDataMask->textLength(13, 1));
        self::assertSame(0, $phpDataMask->textLength(11, 5));
        self::assertSame(0, $phpDataMask->textLength(15, 5));
        self::assertSame(0, $phpDataMask->textLength(12, 0));
    }

    public function test_it_gives_the_body_length_of_a_literal_whose_quotes_are_its_two_ends(): void
    {
        $phpDataMask = PhpDataMask::of("<?php \$a = 'abc';");

        self::assertSame(3, $phpDataMask->literalLength(11, 3));
        self::assertSame(0, $phpDataMask->literalLength(11, 2));
        self::assertSame(0, $phpDataMask->literalLength(11, 4));
        self::assertSame(0, $phpDataMask->literalLength(15, 1));
    }

    #[DataProvider('quotePairCases')]
    public function test_it_tells_whether_two_quotes_are_the_ends_of_one_literal(string $content, int $opening, int $closing, bool $isLiteral): void
    {
        $quotes = array_keys(array_filter(str_split($content), static fn (string $character): bool => "'" === $character));

        self::assertSame($isLiteral, PhpDataMask::of($content)->isStringLiteral($quotes[$opening], $quotes[$closing]));
    }

    /**
     * Quotes are told by their rank among the single quotes of the content.
     *
     * @return iterable<string, array{0: string, 1: int, 2: int, 3: bool}>
     */
    public static function quotePairCases(): iterable
    {
        yield 'the two ends of a php string' => ["<?php \$a = 'ab';", 0, 1, true];
        yield 'two quotes inside a php string' => ['<?php $a = "x \'ab\' y";', 0, 1, true];
        yield 'two quotes of a text' => ["x 'ab' y", 0, 1, true];
        yield 'the opening quote of a php string and a quote inside another' => ['<?php $a = \'ab\' . "\'cd\'";', 0, 2, false];
        yield 'the opening quotes of two php strings' => ["<?php \$a = 'ab' . 'cd';", 0, 2, false];
        yield 'the closing quote of a php string and the opening of the next' => ["<?php \$a = 'ab' . 'cd';", 1, 2, false];
        yield 'the closing quote of a php string and the closing of the next' => ["<?php \$a = 'ab' . 'cd';", 1, 3, false];
        yield 'a quote inside a php string and the opening quote of another' => ['<?php $a = "x \'ab y" . \'cd\';', 0, 1, false];
        yield 'a quote inside a php string and the closing quote of another' => ['<?php $a = "x \'ab y" . \'cd\';', 0, 2, false];
        yield 'the opening quote of a php string and an escaped quote inside it' => ["<?php \$a = 'ab\\'cd';", 0, 1, false];
        yield 'an escaped quote inside a php string and its closing quote' => ["<?php \$a = 'ab\\'cd';", 1, 2, false];
    }
}
