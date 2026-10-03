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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\WorkflowCommandText;

final class WorkflowCommandTextTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function lines(): iterable
    {
        yield 'a legacy command' => ['src/##[warning]forged.php', 'src/#\#[warning]forged.php'];
        yield 'a legacy command behind a hash' => ['###[error]x', '##\#[error]x'];
        yield 'a double colon, which only a line start makes a command' => ['Foo::bar()', 'Foo::bar()'];
    }

    #[DataProvider('lines')]
    public function test_a_line_printed_after_a_prefix_has_its_legacy_commands_defused(string $line, string $defused): void
    {
        self::assertSame($defused, WorkflowCommandText::inLine($line));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function wrappedMessages(): iterable
    {
        yield 'a command the console could wrap to a line start' => ['aaaa ::error title=x::y', 'aaaa :\:error title=x:\:y'];
        yield 'a run of colons' => [':::warning::::x', ':\:\:warning:\:\:\:x'];
        yield 'a legacy command' => ['a ##[warning]x', 'a #\#[warning]x'];
        yield 'a lone colon' => ['a: b', 'a: b'];
    }

    #[DataProvider('wrappedMessages')]
    public function test_a_message_the_console_may_wrap_has_every_command_defused(string $message, string $defused): void
    {
        self::assertSame($defused, WorkflowCommandText::inWrappedMessage($message));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function documents(): iterable
    {
        yield 'a command at a line start' => ["report\n::error::forged\n", "report\n:\\:error::forged\n"];
        yield 'a command behind indentation' => ["report\n    ::stop-commands::x", "report\n    :\\:stop-commands::x"];
        yield 'a command behind a carriage return' => ["report\n\r::add-mask::x", "report\n\r:\\:add-mask::x"];
        yield 'a command after a lone carriage return' => ["report\r::error::x", "report\r:\\:error::x"];
        yield 'a command after a carriage return inside an indented line' => ["a\n  x\r::error::y", "a\n  x\r:\\:error::y"];
        yield 'a command after a Windows line break' => ["report\r\n::error::x", "report\r\n:\\:error::x"];
        yield 'a command behind a no-break space' => ["report\n\u{A0}::error::x", "report\n\u{A0}:\\:error::x"];
        yield 'a command on the first line' => ['::error::x', ':\\:error::x'];
        yield 'a double colon inside a line' => ['    echo Foo::bar();', '    echo Foo::bar();'];
        yield 'a legacy command inside a line' => ['    echo "##[warning]x";', '    echo "#\\#[warning]x";'];
        yield 'text that is not UTF-8' => ["\xFF\n\u{A0}::error::x", "?\n\u{A0}:\\:error::x"];
    }

    #[DataProvider('documents')]
    public function test_a_document_printed_line_by_line_has_its_line_start_and_legacy_commands_defused(string $document, string $defused): void
    {
        self::assertSame($defused, WorkflowCommandText::inDocument($document));
    }

    public function test_a_json_document_keeps_its_meaning_while_its_legacy_commands_are_defused(): void
    {
        $json = (string) json_encode(['title' => 'x ##[warning]forged'], \JSON_PRETTY_PRINT);

        $defused = WorkflowCommandText::inJson($json);

        self::assertStringNotContainsString('##[', $defused);
        self::assertSame(['title' => 'x ##[warning]forged'], json_decode($defused, true));
    }
}
