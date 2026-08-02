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
    /**
     * LLM-produced narrative text is rendered as raw Markdown; an unescaped
     * run of backticks OR tildes (CommonMark allows either as a fence marker,
     * e.g. a ``` or ~~~ fence quoted mid-description) would open a code block
     * that only closes at the next such run — silently swallowing every
     * subsequent finding as inert code text once rendered. Backslash-escaping
     * each backtick/tilde keeps it a literal character instead. CommonMark
     * also passes raw inline HTML through verbatim, so `<`/`>` are entity-
     * encoded too — otherwise a payload like `<img onerror=...>` survives
     * into any downstream Markdown-to-HTML rendering of this report. `#` is
     * escaped too, since a description/attack-vector/remediation field is
     * legitimately multi-paragraph (unlike `title`, which is collapsed to one
     * line by {@see self::heading()}) and an embedded `\n\n## ` would
     * otherwise forge a fake top-level section heading mid-finding. A raw
     * backslash already present right before a backtick/tilde must be escaped
     * *first* — otherwise it combines with the backslash inserted below into
     * an escaped-backslash-then-live-marker sequence CommonMark still parses
     * as an open fence. `[`/`]` are escaped too: CommonMark's
     * `[display text](target)` link syntax needs no fence or heading marker
     * to work, so an unescaped title could forge a live, clickable link
     * straight into the rendered report.
     */
    public static function fences(string $text): string
    {
        $sanitized = TerminalTextSanitizer::stripControlCharacters(mb_scrub($text, 'UTF-8'));
        $backslashesEscaped = str_replace('\\', '\\\\', $sanitized);
        $markerEscaped = str_replace(['`', '~', '#', '<', '>', '[', ']'], ['\\`', '\\~', '\\#', '&lt;', '&gt;', '\\[', '\\]'], $backslashesEscaped);

        return self::setextUnderlines($markerEscaped);
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
     * Backslash escapes do not work inside a CommonMark code span — the
     * standard way to safely wrap arbitrary text in one is a delimiter longer
     * than any backtick run the text contains, padded with a leading space if
     * the text starts with a backtick. `<`/`>` need no manual entity encoding
     * here: CommonMark renders code-span content as literal text and
     * HTML-escapes it automatically. A code span cannot contain a blank line
     * (a blank line is a block-level separator resolved before inline parsing,
     * so it ends the span no matter how wide the delimiter is), so an
     * LLM-sourced `filePath` with an embedded `\n\n` would otherwise break out
     * and render the remainder as live Markdown/HTML — the text is collapsed to
     * a single line and stripped of control/bidi characters first, the same
     * defense the sibling console and HTML renderers apply.
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
     * Escaping `#` (see {@see self::fences()}) blocks a forged ATX heading, but
     * CommonMark also promotes a paragraph line to a heading when the *next*
     * line is a run of only `=` (H1) or `-` (H2) — a setext underline — with no
     * `#` involved. A multi-paragraph description/attack-vector/remediation
     * could therefore still forge a fake section (or, via a `-` run, a `<hr>`
     * thematic break) mid-finding. Any line consisting solely of `=`/`-` (with
     * up to three leading spaces, the CommonMark limit) has its run
     * backslash-escaped so the line is no longer a valid underline yet still
     * renders as the literal characters.
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
