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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

/**
 * Escapes model-written text so it cannot break out of the Markdown construct
 * it is spliced into. Every Markdown renderer goes through it.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class MarkdownTextEscaper
{
    private const string INERT_AT_SIGN = "@\u{2060}";

    public static function fences(string $text): string
    {
        $sanitized = TerminalTextSanitizer::stripControlCharacters(mb_scrub($text, 'UTF-8'));

        return self::setextUnderlines(self::bareAutolinks(self::escapeStructuralMarkers($sanitized)));
    }

    /**
     * Neutralizes code fences, headings, links and raw HTML. Follows `@` with
     * a word joiner so GitHub turns no `@handle` into a mention and no
     * email address into a link. The backslash and `&` are escaped first, so
     * no escape or character reference the text writes stays live.
     */
    private static function escapeStructuralMarkers(string $text): string
    {
        $backslashesEscaped = str_replace('\\', '\\\\', $text);

        return str_replace(
            ['&', '`', '~', '#', '<', '>', '[', ']', '@'],
            ['&amp;', '\\`', '\\~', '\\#', '&lt;', '&gt;', '\\[', '\\]', self::INERT_AT_SIGN],
            $backslashesEscaped,
        );
    }

    /**
     * Encodes the colon of `://` and the dot after `www`, so GFM links no bare
     * URL; an email address is defused at its `@`.
     */
    private static function bareAutolinks(string $text): string
    {
        return preg_replace(['/:(?=\/\/)/', '/(www)\./i'], ['&#58;', '$1&#46;'], $text) ?? $text;
    }

    /**
     * Collapses the text to one line, so a title cannot forge a heading or a
     * rule below the one it fills.
     */
    public static function heading(string $text): string
    {
        return self::fences(str_replace(["\r\n", "\r", "\n"], ' ', $text));
    }

    /**
     * Delimits the text with a backtick run longer than any it holds, then
     * collapses it to one line, since a blank line ends a code span.
     */
    public static function inlineCode(string $text): string
    {
        $text = TerminalTextSanitizer::collapseToSingleLine(mb_scrub($text, 'UTF-8'));
        $delimiter = str_repeat('`', self::longestBacktickRun($text) + 1);
        $padding = str_starts_with($text, '`') ? ' ' : '';

        return \sprintf('%s%s%s%s%s', $delimiter, $padding, $text, $padding, $delimiter);
    }

    /**
     * Strips control characters, a bare `\r` among them, so every line stays
     * inside the indented code block.
     */
    public static function codeBlock(string $text): string
    {
        return implode("\n", array_map(
            static fn (string $line): string => \sprintf('    %s', $line),
            explode("\n", TerminalTextSanitizer::stripControlCharacters(mb_scrub($text, 'UTF-8'))),
        ));
    }

    /**
     * Escapes `|` and collapses the text to one line on top of fences(), so a
     * cell cannot forge a column or a row.
     */
    public static function tableCell(string $text): string
    {
        return str_replace('|', '\\|', self::heading($text));
    }

    /**
     * Escapes `|`, on which GFM splits a row even inside a code span. Outside
     * a table, use inlineCode(): a code span there renders `\|` literally.
     */
    public static function tableInlineCode(string $text): string
    {
        return str_replace('|', '\\|', self::inlineCode($text));
    }

    /**
     * Escapes a line of only `=` or `-`, which would turn the line above it
     * into a setext heading.
     */
    private static function setextUnderlines(string $text): string
    {
        return preg_replace('/(^|\n)( {0,3})(=+|-+)([ \t]*)(?=\n|$)/', '$1$2\\\\$3$4', $text) ?? $text;
    }

    private static function longestBacktickRun(string $text): int
    {
        preg_match_all('/`+/', $text, $matches);

        return [] === $matches[0] ? 0 : max(array_map(\strlen(...), $matches[0]));
    }
}
