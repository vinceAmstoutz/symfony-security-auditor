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
 * U+FFFD is itself a valid character of a PHP identifier, so a Latin-1 `$café` still parses after its invalid byte is replaced.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class Utf8Normalizer
{
    private const int REPLACEMENT_CHARACTER = 0xFFFD;

    public static function normalize(string $bytes): string
    {
        $previous = mb_substitute_character();
        mb_substitute_character(self::REPLACEMENT_CHARACTER);

        try {
            return mb_scrub($bytes, 'UTF-8');
        } finally {
            mb_substitute_character($previous);
        }
    }
}
