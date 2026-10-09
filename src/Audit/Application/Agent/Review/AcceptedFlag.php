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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

/**
 * Reads the `accepted` flag of a reviewer verdict. Beside the JSON booleans it
 * takes the spellings a provider that stringifies JSON booleans, or a model
 * answering in words, plausibly sends. Anything else (`"rejected"`, `"maybe"`,
 * an empty string, a number other than 0 or 1) reads as null: not a verdict.
 * PHP's `(bool)` cast would read every one of those as an acceptance.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AcceptedFlag
{
    private const array ACCEPTING_WORDS = ['true', 'yes', 'y', '1'];

    private const array REJECTING_WORDS = ['false', 'no', 'n', '0'];

    public static function read(mixed $accepted): ?bool
    {
        if (\is_bool($accepted)) {
            return $accepted;
        }

        if (!\is_string($accepted) && !\is_int($accepted)) {
            return null;
        }

        $word = strtolower(trim((string) $accepted));

        if (\in_array($word, self::ACCEPTING_WORDS, true)) {
            return true;
        }

        return \in_array($word, self::REJECTING_WORDS, true) ? false : null;
    }
}
