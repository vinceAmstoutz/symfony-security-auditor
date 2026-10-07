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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Report;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\MarkdownTextEscaper;

final class MarkdownTextEscaperTest extends TestCase
{
    #[DataProvider('bareAutolinks')]
    public function test_it_keeps_a_bare_url_from_becoming_a_live_link(string $text, string $expected): void
    {
        self::assertSame($expected, MarkdownTextEscaper::fences($text));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function bareAutolinks(): iterable
    {
        yield 'an https url' => ['Visit https://evil.example/x now', 'Visit https&#58;//evil.example/x now'];
        yield 'an http url' => ['http://evil.example', 'http&#58;//evil.example'];
        yield 'an ftp url' => ['ftp://evil.example', 'ftp&#58;//evil.example'];
        yield 'every url of a text' => ['a://b and c://d', 'a&#58;//b and c&#58;//d'];
        yield 'a url in parentheses' => ['(https://evil.example)', '(https&#58;//evil.example)'];
        yield 'a www address' => ['Visit www.evil.example now', 'Visit www&#46;evil.example now'];
        yield 'a www address in capitals' => ['WWW.EVIL.example', 'WWW&#46;EVIL.example'];
        yield 'every www address of a text' => ['www.a.example www.b.example', 'www&#46;a.example www&#46;b.example'];
        yield 'an email address' => ['mail a@b.example now', 'mail a&#64;b.example now'];
    }

    #[DataProvider('plainText')]
    public function test_it_leaves_text_that_is_no_bare_url_as_written(string $text): void
    {
        self::assertSame($text, MarkdownTextEscaper::fences($text));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function plainText(): iterable
    {
        yield 'a colon before a single slash' => ['see a:/b'];
        yield 'a colon before a word' => ['ratio 1:2'];
        yield 'a domain without www' => ['see example.com'];
        yield 'www without a dot' => ['see wwwx and www'];
    }
}
