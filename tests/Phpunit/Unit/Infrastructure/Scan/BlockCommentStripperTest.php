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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\BlockCommentStripper;

final class BlockCommentStripperTest extends TestCase
{
    #[DataProvider('commentCases')]
    public function test_it_strips_block_comments_and_carries_the_open_state(string $line, bool $insideBlockComment, string $expectedLine, bool $expectedInside): void
    {
        self::assertSame(
            ['line' => $expectedLine, 'inside_block_comment' => $expectedInside],
            (new BlockCommentStripper())->strip($line, $insideBlockComment),
        );
    }

    /** @return iterable<string, array{0: string, 1: bool, 2: string, 3: bool}> */
    public static function commentCases(): iterable
    {
        yield 'an empty line' => ['', false, '', false];
        yield 'an empty line inside a comment' => ['', true, '', true];
        yield 'a line without a comment' => ['foo();', false, 'foo();', false];
        yield 'a comment in the middle' => ['a /* b */ c', false, 'a  c', false];
        yield 'a comment ending the line' => ['a /* b */', false, 'a ', false];
        yield 'a comment left open' => ['a /* b', false, 'a ', true];
        yield 'the end of a comment opened on an earlier line' => [' b */ c', true, ' c', false];
        yield 'a line inside a comment' => [' b', true, '', true];
        yield 'the end of a comment and the start of the next' => ['*/ x /* y', true, ' x ', true];
        yield 'two comments' => ['a /* b */ c /* d */ e', false, 'a  c  e', false];
        yield 'an opener that closes itself only after a slash' => ['/*/ x', false, '', true];
        yield 'a comment opener inside a literal' => ["\$a = '/* not */'; b", false, "\$a = '/* not */'; b", false];
        yield 'a comment opener inside a literal, then a comment' => ["'x /*' /* y */ z", false, "'x /*'  z", false];
        yield 'an opener and a closer inside literals, then a comment' => ["\"/*\" '*/' /* c */ d", false, "\"/*\" '*/'  d", false];
        yield 'a literal before a comment' => ["'a' /* b */", false, "'a' ", false];
        yield 'two literals before a comment' => ["'a''b' /* c */ d", false, "'a''b'  d", false];
        yield 'a quote inside a comment opens no literal' => ["/* it's */ x /* y */ z", false, ' x  z', false];
        yield 'a literal after a comment holding a quote' => ["/* it's */ foo('/*')", false, " foo('/*')", false];
        yield 'an unterminated quote before a comment' => ["'abc /* x */ y", false, "'abc  y", false];
        yield 'an unterminated quote after a comment' => ["/* */ 'a /* b */ c", false, " 'a  c", false];
        yield 'an escaped quote before a comment' => ["'a\\'/* b */ c", false, "'a\\' c", false];
        yield 'an unterminated quote of one kind before a literal of the other' => ["\"a\" 'b /* c */ d", false, "\"a\" 'b  d", false];
    }

    public function test_it_reads_a_line_of_thousands_of_comments_between_escaped_quotes_in_one_pass(): void
    {
        $line = str_repeat("/**/\\'", 20000).'code';

        self::assertSame(
            ['line' => str_repeat("\\'", 20000).'code', 'inside_block_comment' => false],
            (new BlockCommentStripper())->strip($line, false),
        );
    }
}
