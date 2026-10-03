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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

/**
 * Text quoted back to a terminal from the audited repository's config — a
 * key, the offending line of a YAML error — has the characters a terminal
 * reads as control sequences, breaks a line on or reorders it escaped: the
 * ASCII control bytes, the eight-bit C1 controls (U+0080–U+009F), the line
 * and paragraph separators (U+2028, U+2029) and the bidirectional overrides
 * and marks (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069). Any
 * other UTF-8 text, `équipe` included, reads as written. Text that is not
 * valid UTF-8 has every byte above ASCII escaped, since its C1 bytes cannot
 * be told apart from the rest. Unlike the report's `TerminalTextSanitizer`,
 * which drops these characters from findings, a refusal escapes them, so the
 * user sees what the refused text held.
 *
 * `isPlain()` is the rule a value typed on the command line or read from the
 * audited repository's config must meet before it is quoted back or reaches a
 * setting: valid UTF-8 holding none of these characters but a tab.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class TerminalText
{
    private const string ASCII_CONTROL_BYTES = "\0..\37\177";

    private const string HIGH_BYTES = "\200..\377";

    private const string UTF8_C1_CONTROL_OR_BIDI_OVERRIDE = '/\xC2[\x80-\x9F]|\xD8\x9C|\xE2\x80[\x8E\x8F\xA8-\xAE]|\xE2\x81[\xA6-\xA9]/';

    private const string PLAIN_TEXT = '/^[^\x00-\x08\x0A-\x1F\x7F\x{80}-\x{9F}\x{61C}\x{200E}\x{200F}\x{2028}-\x{202E}\x{2066}-\x{2069}]*$/Du';

    public static function isPlain(string $text): bool
    {
        return 1 === preg_match(self::PLAIN_TEXT, $text);
    }

    public static function escaped(string $text): string
    {
        $escaped = addcslashes($text, self::ASCII_CONTROL_BYTES);
        if (1 !== preg_match('//u', $escaped)) {
            return addcslashes($escaped, self::HIGH_BYTES);
        }

        return preg_replace_callback(
            self::UTF8_C1_CONTROL_OR_BIDI_OVERRIDE,
            static fn (array $match): string => addcslashes($match[0], self::HIGH_BYTES),
            $escaped,
        ) ?? addcslashes($escaped, self::HIGH_BYTES);
    }
}
