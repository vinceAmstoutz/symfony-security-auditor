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
 * Shared defenses for any LLM-sourced text about to reach a real terminal, used
 * by the console report and the live progress narration. Bypassing Symfony
 * Console's `<tag>` formatter (`OUTPUT_RAW`, or `OutputFormatter::escape()` on
 * `<`/`>` alone) does not strip a raw ANSI escape byte, a carriage return or a
 * Unicode bidi override already in the string — any of which let a crafted
 * finding overwrite adjacent output, forge a status line, or visually reorder
 * its own text.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class TerminalTextSanitizer
{
    public static function stripControlCharacters(string $text): string
    {
        return preg_replace('/[\x{0}-\x{8}\x{B}-\x{1F}\x{7F}-\x{9F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $text) ?? $text;
    }

    /**
     * `\R` under the `/u` modifier collapses every Unicode newline sequence
     * (CR, LF, CRLF, NEL, LS, PS), not just the ASCII ones a plain
     * `str_replace()` would catch.
     */
    public static function collapseToSingleLine(string $text): string
    {
        return self::stripControlCharacters(preg_replace('/\R/u', ' ', $text) ?? $text);
    }
}
