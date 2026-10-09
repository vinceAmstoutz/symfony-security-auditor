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
 * Where a line reader stands relative to the string literals of a line, one
 * character at a time. A quote opens a literal only when an unescaped quote of
 * its kind comes after it on the line, otherwise it is plain text: that is
 * decided by {@see self::closingLimits()}, once per line, so no quote is ever
 * tried and dropped and a line is read in a single pass.
 */
final readonly class LiteralScanState
{
    private function __construct(
        private string $quote = '',
        private bool $escaped = false,
    ) {}

    public static function outside(): self
    {
        return new self();
    }

    /**
     * The offset of the last unescaped quote of each kind, the one that closes
     * the last literal that kind can open; a quote at or after it opens none.
     * A quote is unescaped when an even number of backslashes comes right
     * before it.
     *
     * @return array<string, int>
     */
    public static function closingLimits(string $line): array
    {
        $reversed = strrev($line);

        return [
            "'" => self::lastUnescapedQuoteAt($reversed, "'"),
            '"' => self::lastUnescapedQuoteAt($reversed, '"'),
        ];
    }

    /**
     * @param array<string, int> $closingLimits
     */
    public function next(string $char, int $offset, array $closingLimits): self
    {
        if (!$this->isInside()) {
            return $this->opensLiteral($char, $offset, $closingLimits) ? new self($char) : $this;
        }

        if (!$this->escaped && $char === $this->quote) {
            return self::outside();
        }

        return new self($this->quote, !$this->escaped && '\\' === $char);
    }

    public function isInside(): bool
    {
        return '' !== $this->quote;
    }

    private static function lastUnescapedQuoteAt(string $reversedLine, string $quote): int
    {
        if (1 !== preg_match(\sprintf('/%s(?=(?:\\\\\\\\)*+(?!\\\\))/', $quote), $reversedLine, $match, \PREG_OFFSET_CAPTURE)) {
            return \PHP_INT_MIN;
        }

        return \strlen($reversedLine) - 1 - $match[0][1];
    }

    /**
     * @param array<string, int> $closingLimits
     */
    private function opensLiteral(string $char, int $offset, array $closingLimits): bool
    {
        return \array_key_exists($char, $closingLimits) && $offset < $closingLimits[$char];
    }
}
