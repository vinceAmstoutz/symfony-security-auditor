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
 * Defuses the GitHub Actions workflow commands of text from the audited
 * repository or the model (`::` starting a line, `##[` anywhere) with a
 * backslash, so the text still reads as written. Each method suits where the
 * text lands: after a prefix, in a message the console may wrap, in a
 * document or in JSON.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class WorkflowCommandText
{
    private const string LEGACY_MARKER = '/#(?=#\[)/';

    private const string COLON_BEFORE_A_COLON = '/:(?=:)/';

    private const string LINE_START_MARKER = '/(*ANYCRLF)^([^\S\r\n]*)::/mu';

    private const string DEFUSED_LINE_START = '$1:\\\\:';

    public static function inLine(string $text): string
    {
        return preg_replace(self::LEGACY_MARKER, '#\\\\', $text) ?? $text;
    }

    public static function inWrappedMessage(string $text): string
    {
        return self::inLine(preg_replace(self::COLON_BEFORE_A_COLON, ':\\\\', $text) ?? $text);
    }

    /**
     * Starts a line after a carriage return too and looks through Unicode
     * whitespace, as the runner does; scrubs text that is not UTF-8 first.
     */
    public static function inDocument(string $text): string
    {
        $scrubbed = mb_scrub($text, 'UTF-8');

        return self::inLine(preg_replace(self::LINE_START_MARKER, self::DEFUSED_LINE_START, $scrubbed) ?? $scrubbed);
    }

    /**
     * Escapes the marker in a JSON string, which reads back as written.
     */
    public static function inJson(string $json): string
    {
        return str_replace('##[', '#\\u0023[', $json);
    }
}
