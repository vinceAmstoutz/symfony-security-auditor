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
    public function test_it_replaces_each_invalid_byte_with_the_replacement_character(string $invalid, string $expected): void
    {
        self::assertSame($expected, Utf8Normalizer::normalize($invalid));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidTexts(): iterable
    {
        yield 'a Latin-1 letter' => ["caf\xE9", "caf\u{FFFD}"];
        yield 'a byte no UTF-8 sequence starts with' => ["Fo\xFFo.php", "Fo\u{FFFD}o.php"];
        yield 'a continuation byte on its own' => ["a\x80b", "a\u{FFFD}b"];
        yield 'valid and invalid text mixed' => ["é\xE9é", "é\u{FFFD}é"];
        yield 'two separate invalid bytes' => ["\xE9 and \xE8", "\u{FFFD} and \u{FFFD}"];
    }

    public function test_it_leaves_the_substitute_character_setting_as_it_found_it(): void
    {
        $before = mb_substitute_character();

        Utf8Normalizer::normalize("caf\xE9");

        self::assertSame($before, mb_substitute_character());
    }
}
