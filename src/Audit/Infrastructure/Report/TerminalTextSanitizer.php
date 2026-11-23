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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\ConsoleProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\PlainProgressReporter;

/**
 * Strips the control characters and bidirectional overrides of model-written
 * text before {@see ConsoleReportRenderer}, {@see ConsoleProgressReporter} or
 * {@see PlainProgressReporter} prints it, so a finding cannot overwrite output,
 * forge a status line or reorder its own text. Symfony Console's escaping
 * strips none of them.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class TerminalTextSanitizer
{
    public static function stripControlCharacters(string $text): string
    {
        return preg_replace('/[\x{0}-\x{8}\x{B}-\x{1F}\x{7F}-\x{9F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $text) ?? $text;
    }

    /**
     * Replaces every Unicode line break, NEL and the line and paragraph
     * separators included, with a space.
     */
    public static function collapseToSingleLine(string $text): string
    {
        return self::stripControlCharacters(preg_replace('/\R/u', ' ', $text) ?? $text);
    }
}
