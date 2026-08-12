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
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Tracks the open-paren depth left behind by a retained line, ignoring parens
 * inside string literals and trailing comments.
 */
final readonly class ParenContinuationTracker
{
    public function __construct(
        private StringLiteralMasker $stringLiteralMasker = new StringLiteralMasker(),
    ) {}

    /**
     * @return array{0: int, 1: ?string}
     */
    public function advance(bool $retain, string $line, int $openParenDepth, ?string $openStringDelimiter): array
    {
        if (!$retain) {
            return [$openParenDepth, $openStringDelimiter];
        }

        $parenState = $this->parenDelta($line, $openStringDelimiter);

        return [max(0, $openParenDepth + $parenState['delta']), $parenState['open_string_delimiter']];
    }

    /**
     * @return array{delta: int, open_string_delimiter: ?string}
     */
    private function parenDelta(string $line, ?string $openStringDelimiter): array
    {
        if (null !== $openStringDelimiter) {
            $closingQuoteOffset = $this->closingQuoteOffset($line, $openStringDelimiter);
            if (null === $closingQuoteOffset) {
                return ['delta' => 0, 'open_string_delimiter' => $openStringDelimiter];
            }

            $line = substr($line, $closingQuoteOffset + 1);
        }

        $withoutStringLiterals = $this->stringLiteralMasker->strip($line);
        $withoutStringLiterals = $this->stripTrailingComment($withoutStringLiterals);

        $danglingQuoteOffset = $this->danglingQuoteOffset($withoutStringLiterals);
        $nextOpenStringDelimiter = null;
        if (null !== $danglingQuoteOffset) {
            $nextOpenStringDelimiter = $withoutStringLiterals[$danglingQuoteOffset];
            $withoutStringLiterals = substr($withoutStringLiterals, 0, $danglingQuoteOffset);
        }

        return [
            'delta' => substr_count($withoutStringLiterals, '(') - substr_count($withoutStringLiterals, ')'),
            'open_string_delimiter' => $nextOpenStringDelimiter,
        ];
    }

    private function closingQuoteOffset(string $line, string $quoteChar): ?int
    {
        $pattern = \sprintf('/^(?:\\\\.|[^%s\\\\])*%s/', $quoteChar, $quoteChar);
        if (1 !== preg_match($pattern, $line, $matches)) {
            return null;
        }

        return \strlen($matches[0]) - 1;
    }

    private function danglingQuoteOffset(string $text): ?int
    {
        if (1 !== preg_match('/[\'"]/', $text, $matches, \PREG_OFFSET_CAPTURE)) {
            return null;
        }

        return $matches[0][1];
    }

    private function stripTrailingComment(string $text): string
    {
        $offsets = array_filter(
            [$this->falseToNull(strpos($text, '//')), $this->hashCommentOffset($text)],
            static fn (?int $offset): bool => null !== $offset,
        );

        return [] === $offsets ? $text : substr($text, 0, min($offsets));
    }

    // Negative lookahead: `#[` starts an attribute, not a comment.
    private function hashCommentOffset(string $text): ?int
    {
        return 1 === preg_match('/#(?!\[)/', $text, $matches, \PREG_OFFSET_CAPTURE) ? $matches[0][1] : null;
    }

    private function falseToNull(int|false $offset): ?int
    {
        return false === $offset ? null : $offset;
    }
}
