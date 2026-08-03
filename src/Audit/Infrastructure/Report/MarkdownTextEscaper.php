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
 * Renders LLM-authored text into Markdown without letting it escape the
 * construct it was spliced into. Shared by every Markdown-emitting renderer, so
 * a new one inherits these defenses instead of restating them.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class MarkdownTextEscaper
{
    public static function fences(string $text): string
    {
        $sanitized = TerminalTextSanitizer::stripControlCharacters(mb_scrub($text, 'UTF-8'));

        return self::setextUnderlines(self::escapeStructuralMarkers($sanitized));
    }

    /**
     * A backtick/tilde run would open a code fence, `#` a fake heading, and
     * `[`/`]` a live link — each would swallow or rewrite everything rendered
     * after it. `<`/`>` are HTML-entity-encoded since CommonMark passes raw
     * inline HTML through verbatim. A backslash already present is escaped
     * first, so it can't combine with an escape added below into a sequence
     * CommonMark still parses as live.
     */
    private static function escapeStructuralMarkers(string $text): string
    {
        $backslashesEscaped = str_replace('\\', '\\\\', $text);

        return str_replace(
            ['`', '~', '#', '<', '>', '[', ']'],
            ['\\`', '\\~', '\\#', '&lt;', '&gt;', '\\[', '\\]'],
            $backslashesEscaped,
        );
    }

    /**
     * A finding's title is spliced directly into a single-line heading, with no
     * surrounding code fence or paragraph break to contain it — an embedded
     * newline could forge a fake heading or horizontal rule as unguarded
     * top-level Markdown right where the title was expected.
     */
    public static function heading(string $text): string
    {
        return self::fences(str_replace(["\r\n", "\r", "\n"], ' ', $text));
    }

    /**
     * A code span can't use backslash escapes, so the delimiter is instead a
     * backtick run longer than any the text contains, padded with a leading
     * space if the text starts with a backtick; `<`/`>` need no encoding since
     * CommonMark renders span content as literal text automatically. A blank
     * line still ends a span regardless of delimiter width, so the text is
     * collapsed to a single line first, the same defense the sibling renderers
     * apply.
     */
    public static function inlineCode(string $text): string
    {
        $text = TerminalTextSanitizer::collapseToSingleLine(mb_scrub($text, 'UTF-8'));
        $delimiter = str_repeat('`', self::longestBacktickRun($text) + 1);
        $padding = str_starts_with($text, '`') ? ' ' : '';

        return \sprintf('%s%s%s%s%s', $delimiter, $padding, $text, $padding, $delimiter);
    }

    /**
     * A bare `\r` (0x0D not part of a `\r\n`) is a CommonMark line ending, so
     * an LLM-sourced code snippet containing one would split inside a "line"
     * and land the remainder at column 0 — outside the four-space indent — as
     * live Markdown/HTML. Control characters are stripped first (the same
     * {@see TerminalTextSanitizer} defense the inline paths apply), so every
     * retained `\n`-delimited line stays inside the indented code block.
     */
    public static function codeBlock(string $text): string
    {
        return implode("\n", array_map(
            static fn (string $line): string => \sprintf('    %s', $line),
            explode("\n", TerminalTextSanitizer::stripControlCharacters(mb_scrub($text, 'UTF-8'))),
        ));
    }

    /**
     * A Markdown table cell is delimited by `|`, and a newline ends the row
     * altogether — either would let one cell's text forge extra columns or
     * extra rows. `|` is backslash-escaped and the text is collapsed to a
     * single line on top of the {@see self::fences()} defenses.
     */
    public static function tableCell(string $text): string
    {
        return str_replace('|', '\\|', self::heading($text));
    }

    /**
     * Escaping `#` blocks a forged ATX heading, but CommonMark also promotes a
     * paragraph line to a heading when the *next* line is a run of only `=`
     * (H1) or `-` (H2) — a setext underline, no `#` involved. Any line
     * consisting solely of `=`/`-` (up to three leading spaces, the CommonMark
     * limit) has its run backslash-escaped so it renders as literal characters
     * instead.
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
