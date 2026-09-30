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
 * A GitHub Actions runner reads a job-log line that starts with `::`, leading
 * whitespace aside, as a workflow command, and the legacy `##[command]` form
 * wherever it sits in a line. Text from the audited repository or the model
 * is defused before it reaches such a log: a backslash breaks each marker, so
 * the text still reads as written. Which markers need breaking depends on
 * where the text lands — after a prefix of ours, in a message the console may
 * wrap anywhere, in a document printed line by line, or inside JSON strings.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
     * The runner starts a line after a carriage return too, and trims Unicode
     * whitespace, so both are looked through; text that is not UTF-8 is
     * scrubbed first, since only valid UTF-8 can be matched for that
     * whitespace.
     */
    public static function inDocument(string $text): string
    {
        $scrubbed = mb_scrub($text, 'UTF-8');

        return self::inLine(preg_replace(self::LINE_START_MARKER, self::DEFUSED_LINE_START, $scrubbed) ?? $scrubbed);
    }

    /**
     * The marker can only sit inside a JSON string, where `#` reads back
     * as the `#` it replaces.
     */
    public static function inJson(string $json): string
    {
        return str_replace('##[', '#\\u0023[', $json);
    }
}
