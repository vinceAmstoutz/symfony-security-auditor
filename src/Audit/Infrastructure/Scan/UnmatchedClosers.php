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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use CompileError;

/**
 * Tells whether a PHP source holds so many unmatched closing brackets that PHP's tokenizer stalls on
 * it (seconds for 16,000 stray `)`). Counts the surplus without lexing. A source past the limit that
 * PHP's parser accepts keeps its surplus in comments, strings or inline HTML and is safe to tokenize.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class UnmatchedClosers
{
    public const int LIMIT = 1000;

    private const array CLOSER_OF_OPENER = ['(' => ')', '[' => ']', '{' => '}'];

    public static function exceedLimit(string $source): bool
    {
        return self::LIMIT < self::surplus($source) && !self::parses($source);
    }

    private static function surplus(string $source): int
    {
        $surplus = 0;
        foreach (self::CLOSER_OF_OPENER as $opener => $closer) {
            $surplus += max(0, substr_count($source, $closer) - substr_count($source, $opener));
        }

        return $surplus;
    }

    private static function parses(string $source): bool
    {
        try {
            return [] !== token_get_all($source, \TOKEN_PARSE);
        } catch (CompileError) {
            return false;
        }
    }
}
