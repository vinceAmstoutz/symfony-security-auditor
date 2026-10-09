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

/**
 * Tells whether a PHP source holds so many closing brackets without an opening one that PHP's own
 * tokenizer stalls on it: the lexer raises one ParseError per stray closer and chains it onto the
 * previous one, so `<?php ` followed by 16,000 `)` takes seconds and 32,000 half a minute, whatever
 * the size cap. The surplus of closers over openers, kind by kind, counted over the raw characters
 * without lexing, is cheap, and real code stays far below the limit.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class UnmatchedClosers
{
    public const int LIMIT = 1000;

    private const array CLOSER_OF_OPENER = ['(' => ')', '[' => ']', '{' => '}'];

    public static function exceedLimit(string $source): bool
    {
        $surplus = 0;
        foreach (self::CLOSER_OF_OPENER as $opener => $closer) {
            $surplus += max(0, substr_count($source, $closer) - substr_count($source, $opener));
        }

        return self::LIMIT < $surplus;
    }
}
