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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\TerminalText;

final class TerminalTextTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function escapedTexts(): iterable
    {
        yield 'an ASCII escape sequence' => ["a\e]0;x\x07b", 'a\033]0;x\ab'];
        yield 'a line break' => ["a\nb", 'a\nb'];
        yield 'the delete byte' => ["a\x7Fb", 'a\177b'];
        yield 'the first eight-bit control' => ["a\u{80}b", 'a\302\200b'];
        yield 'the eight-bit control sequence introducer' => ["a\u{9B}2J", 'a\302\2332J'];
        yield 'the last eight-bit control' => ["a\u{9F}b", 'a\302\237b'];
        yield 'the Arabic letter mark' => ["a\u{61C}b", 'a\330\234b'];
        yield 'the left-to-right mark' => ["a\u{200E}b", 'a\342\200\216b'];
        yield 'the right-to-left mark' => ["a\u{200F}b", 'a\342\200\217b'];
        yield 'the line separator' => ["a\u{2028}b", 'a\342\200\250b'];
        yield 'the paragraph separator' => ["a\u{2029}b", 'a\342\200\251b'];
        yield 'the first bidirectional embedding' => ["a\u{202A}b", 'a\342\200\252b'];
        yield 'the right-to-left override' => ["a\u{202E}b", 'a\342\200\256b'];
        yield 'the first bidirectional isolate' => ["a\u{2066}b", 'a\342\201\246b'];
        yield 'the pop directional isolate' => ["a\u{2069}b", 'a\342\201\251b'];
        yield 'text that is not UTF-8' => ["a\xFFb\u{E9}", 'a\377b\303\251'];
    }

    #[DataProvider('escapedTexts')]
    public function test_it_escapes_what_a_terminal_reads_as_a_control_sequence(string $text, string $escaped): void
    {
        self::assertSame($escaped, TerminalText::escaped($text));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function textsReadAsWritten(): iterable
    {
        yield 'an accented instance name' => ['équipe'];
        yield 'a dash and accents' => ['contrôle — accès'];
        yield 'the first character after the eight-bit controls' => ["a\u{A0}b"];
        yield 'the character before the Arabic letter mark' => ["a\u{61B}b"];
        yield 'the character before the left-to-right mark' => ["a\u{200D}b"];
        yield 'the character after the right-to-left mark' => ["a\u{2010}b"];
        yield 'the character before the line separator' => ["a\u{2027}b"];
        yield 'the character after the bidirectional overrides' => ["a\u{202F}b"];
        yield 'the character before the bidirectional isolates' => ["a\u{2065}b"];
        yield 'the character after the bidirectional isolates' => ["a\u{206A}b"];
        yield 'plain ASCII' => ['generic.my_gateway'];
    }

    #[DataProvider('textsReadAsWritten')]
    public function test_it_leaves_any_other_utf8_text_as_written(string $text): void
    {
        self::assertSame($text, TerminalText::escaped($text));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function plainTexts(): iterable
    {
        yield 'no text at all' => [''];
        yield 'a tab' => ["a\tb"];
        yield 'a space and a tilde' => ['a ~b'];
        yield 'an accented instance name' => ['équipe'];
        yield 'the first character after the eight-bit controls' => ["a\u{A0}b"];
        yield 'the character before the Arabic letter mark' => ["a\u{61B}b"];
        yield 'the character before the left-to-right mark' => ["a\u{200D}b"];
        yield 'the character after the right-to-left mark' => ["a\u{2010}b"];
        yield 'the character before the line separator' => ["a\u{2027}b"];
        yield 'the character after the bidirectional overrides' => ["a\u{202F}b"];
        yield 'the character before the bidirectional isolates' => ["a\u{2065}b"];
        yield 'the character after the bidirectional isolates' => ["a\u{206A}b"];
    }

    #[DataProvider('plainTexts')]
    public function test_text_holding_no_control_character_but_a_tab_is_plain(string $text): void
    {
        self::assertTrue(TerminalText::isPlain($text));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function textsThatAreNotPlain(): iterable
    {
        yield 'a null byte' => ["a\0b"];
        yield 'a backspace' => ["a\x08b"];
        yield 'a line feed' => ["a\n::stop-commands::b"];
        yield 'a trailing line feed' => ["ab\n"];
        yield 'a carriage return' => ["a\rb"];
        yield 'the last ASCII control' => ["a\x1Fb"];
        yield 'the delete byte' => ["a\x7Fb"];
        yield 'the first eight-bit control' => ["a\u{80}b"];
        yield 'the last eight-bit control' => ["a\u{9F}b"];
        yield 'the Arabic letter mark' => ["a\u{61C}b"];
        yield 'the left-to-right mark' => ["a\u{200E}b"];
        yield 'the right-to-left mark' => ["a\u{200F}b"];
        yield 'the line separator' => ["a\u{2028}b"];
        yield 'the paragraph separator' => ["a\u{2029}b"];
        yield 'the first bidirectional embedding' => ["a\u{202A}b"];
        yield 'the right-to-left override' => ["a\u{202E}b"];
        yield 'the first bidirectional isolate' => ["a\u{2066}b"];
        yield 'the pop directional isolate' => ["a\u{2069}b"];
        yield 'text that is not UTF-8' => ["a\xFFb"];
    }

    #[DataProvider('textsThatAreNotPlain')]
    public function test_text_holding_a_control_character_a_line_break_or_a_bidirectional_override_is_not_plain(string $text): void
    {
        self::assertFalse(TerminalText::isPlain($text));
    }
}
