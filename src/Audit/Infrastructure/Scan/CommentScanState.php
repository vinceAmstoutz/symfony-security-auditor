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
 * Where a line reader stands relative to the block comments and the string
 * literals of a line, one character at a time. A `/*` inside a literal opens
 * no comment, and a quote inside a comment opens no literal.
 */
final readonly class CommentScanState
{
    private function __construct(
        private int $commentEndsAt,
        private bool $commentIsLeftOpen,
        private LiteralScanState $literalScanState,
    ) {}

    public static function start(string $line, bool $insideComment): self
    {
        return $insideComment ? self::commentFrom($line, 0) : new self(\PHP_INT_MIN, false, LiteralScanState::outside());
    }

    /**
     * @param array<string, int> $closingLimits
     */
    public function advance(string $line, int $offset, string $char, array $closingLimits): self
    {
        if ($this->swallows($offset)) {
            return $this;
        }

        if (!$this->literalScanState->isInside() && '/' === $char && '*' === substr($line, $offset + 1, 1)) {
            return self::commentFrom($line, $offset + 2);
        }

        return new self($this->commentEndsAt, $this->commentIsLeftOpen, $this->literalScanState->next($char, $offset, $closingLimits));
    }

    public function swallows(int $offset): bool
    {
        return $offset < $this->commentEndsAt;
    }

    public function endsInsideComment(): bool
    {
        return $this->commentIsLeftOpen;
    }

    private static function commentFrom(string $line, int $bodyStart): self
    {
        $closerAt = strpos($line, '*/', $bodyStart);

        return false === $closerAt
            ? new self(\PHP_INT_MAX, true, LiteralScanState::outside())
            : new self($closerAt + 2, false, LiteralScanState::outside());
    }
}
