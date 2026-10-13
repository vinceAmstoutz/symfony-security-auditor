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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Utf8Normalizer;

final class Utf8NormalizerTest extends TestCase
{
    #[DataProvider('validTexts')]
    public function test_it_returns_valid_utf8_text_untouched(string $text): void
    {
        self::assertSame($text, Utf8Normalizer::normalize($text));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validTexts(): iterable
    {
        yield 'empty' => [''];
        yield 'ascii with a NUL byte' => ["<?php\n\$a = 1;\0\n"];
        yield 'accented letters' => ['café über señor'];
        yield 'symbols and astral characters' => ['日本語 ☕ 😀'];
        yield 'the replacement character itself' => ["a\u{FFFD}b"];
    }

    #[DataProvider('invalidTexts')]
    public function test_it_writes_each_invalid_byte_as_the_latin1_character_of_that_byte(string $invalid, string $expected): void
    {
        self::assertSame($expected, Utf8Normalizer::normalize($invalid));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidTexts(): iterable
    {
        yield 'a Latin-1 letter' => ["caf\xE9", 'café'];
        yield 'a byte no UTF-8 sequence starts with' => ["Fo\xFFo.php", 'Foÿo.php'];
        yield 'a continuation byte on its own' => ["a\x80b", "a\u{80}b"];
        yield 'valid and invalid text mixed' => ["\u{E8}\xE9\u{E8}", 'èéè'];
        yield 'two separate invalid bytes' => ["\xE9 and \xE8", 'é and è'];
        yield 'a truncated sequence, byte by byte' => ["\xE9\x80b", "é\u{80}b"];
        yield 'an overlong encoding' => ["\xC0\xAF", 'À¯'];
        yield 'an encoded surrogate' => ["\xED\xA0\x80", "í\u{A0}\u{80}"];
        yield 'a code point past U+10FFFF' => ["\xF4\x90\x80\x80", "ô\u{90}\u{80}\u{80}"];
        yield 'a valid character right after an invalid lead byte' => ["\xE9\u{E9}\u{65E5}", 'éé日'];
        yield 'invalid bytes around a long valid run' => ["\xE9".str_repeat('日a', 300)."\xE8", 'é'.str_repeat('日a', 300).'è'];
    }

    public function test_a_valid_run_of_a_million_characters_between_invalid_bytes_is_kept_whole(): void
    {
        $valid = str_repeat('日', 1_100_000);

        self::assertSame('é'.$valid.'è', Utf8Normalizer::normalize("\xE9".$valid."\xE8"));
    }

    public function test_texts_that_differ_only_in_their_invalid_bytes_stay_different(): void
    {
        self::assertNotSame(Utf8Normalizer::normalize("Admin\xE8.php"), Utf8Normalizer::normalize("Admin\xE9.php"));
    }

    #[DataProvider('unambiguousTexts')]
    public function test_text_whose_repair_reads_back_one_way_only_is_not_ambiguous(string $text): void
    {
        self::assertFalse(Utf8Normalizer::isAmbiguous($text));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unambiguousTexts(): iterable
    {
        yield 'valid text with accented letters' => ['café über'];
        yield 'invalid bytes and only ASCII' => ["caf\xE9 and caf\xE8"];
        yield 'invalid bytes and characters past U+00FF' => ["\xE9 \u{100} \u{20AC} \u{65E5}"];
        yield 'invalid bytes and the last ASCII character' => ["\xE9 \x7F"];
    }

    #[DataProvider('ambiguousTexts')]
    public function test_invalid_bytes_beside_a_character_they_could_be_repaired_into_make_the_text_ambiguous(string $text): void
    {
        self::assertTrue(Utf8Normalizer::isAmbiguous($text));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ambiguousTexts(): iterable
    {
        yield 'the same letter, invalid and valid' => ["\$id\xE9 = \$id\u{E9};"];
        yield 'U+0080, the first character a byte is repaired into' => ["\xE9 \u{80}"];
        yield 'U+00FF, the last character a byte is repaired into' => ["\xE9 \u{FF}"];
        yield 'the valid character first' => ["\u{A0} \xFF"];
    }
}
