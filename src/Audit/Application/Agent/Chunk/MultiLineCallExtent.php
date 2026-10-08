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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk;

/**
 * Names the lines a statement spans from the line it starts on: every line
 * that follows while a parenthesis opened on the way is still open. String
 * literals and comments, which may span lines themselves, never count. A
 * statement whose parentheses are never closed spans its first line only, and
 * so does one that stays open past the next {@see self::MAX_LOOKAHEAD_LINES}
 * lines: the cost of one statement is bounded, not the length of the file.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class MultiLineCallExtent
{
    private const string TOKEN_PATTERN = '~/\*.*?\*/|//[^\n]*|#(?!\[)[^\n]*|\'(?:[^\'\\\\]++|\\\\.)*+\'|"(?:[^"\\\\]++|\\\\.)*+"|[()]|\n~s';

    private const array PAREN_DELTAS = ['(' => 1, ')' => -1];

    public const int MAX_LOOKAHEAD_LINES = 200;

    /**
     * @param list<string> $lines
     *
     * @return list<int> the indexes of the lines the statement starting at $startIndex spans
     */
    public function lineIndexes(array $lines, int $startIndex): array
    {
        $endIndex = $this->endIndex(implode("\n", \array_slice($lines, $startIndex, self::MAX_LOOKAHEAD_LINES)), $startIndex);

        return array_keys(\array_slice($lines, $startIndex, $endIndex - $startIndex + 1, true));
    }

    private function endIndex(string $text, int $startIndex): int
    {
        $depth = 0;
        $lineIndex = $startIndex;
        foreach ($this->tokens($text) as $token) {
            if ("\n" === $token && $depth <= 0) {
                return $lineIndex;
            }

            $depth += self::PAREN_DELTAS[$token] ?? 0;
            $lineIndex += substr_count($token, "\n");
        }

        return $depth <= 0 ? $lineIndex : $startIndex;
    }

    /**
     * @return list<string>
     */
    private function tokens(string $text): array
    {
        preg_match_all(self::TOKEN_PATTERN, $text, $matches);

        return $matches[0];
    }
}
