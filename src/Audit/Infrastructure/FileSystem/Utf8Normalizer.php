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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem;

/**
 * Writes each byte that is not part of a valid UTF-8 sequence as the Latin-1
 * character of that byte, so two names or identifiers that differ only in
 * such bytes stay different, and a Latin-1 `$café` still parses.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class Utf8Normalizer
{
    // PCRE counts every repetition of a group against its match limit, so a long valid run is matched in pieces.
    private const string VALID_RUN_OR_INVALID_BYTE = '/(?<valid>(?:[\x00-\x7F]++|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2}){1,100}+)|[\x80-\xFF]/';

    private const string CHARACTER_A_BYTE_IS_REPAIRED_INTO = '/[\xC2\xC3][\x80-\xBF]/';

    public static function normalize(string $bytes): string
    {
        return preg_replace_callback(
            self::VALID_RUN_OR_INVALID_BYTE,
            static fn (array $match): string => $match['valid'] ?? mb_chr(\ord($match[0]), 'UTF-8'),
            $bytes,
        ) ?? $bytes;
    }

    /**
     * Whether the repaired text could read two different byte sequences as
     * one: the bytes are not valid UTF-8 and already hold, as valid UTF-8, a
     * character an invalid byte is repaired into.
     */
    public static function isAmbiguous(string $bytes): bool
    {
        return !mb_check_encoding($bytes, 'UTF-8') && 1 === preg_match(self::CHARACTER_A_BYTE_IS_REPAIRED_INTO, $bytes);
    }
}
