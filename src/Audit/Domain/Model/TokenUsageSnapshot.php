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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

use InvalidArgumentException;

/**
 * Immutable snapshot of input/output token counts at a point in time.
 *
 * Returned by `TokenUsageRecorder::snapshot()` to expose cumulative usage
 * without allowing the caller to mutate the recorder's internal state.
 */
final readonly class TokenUsageSnapshot
{
    private function __construct(
        private int $inputTokens,
        private int $outputTokens,
    ) {}

    public static function of(int $inputTokens, int $outputTokens): self
    {
        if ($inputTokens < 0) {
            throw new InvalidArgumentException(\sprintf('Input tokens must be >= 0, got %d', $inputTokens));
        }

        if ($outputTokens < 0) {
            throw new InvalidArgumentException(\sprintf('Output tokens must be >= 0, got %d', $outputTokens));
        }

        return new self($inputTokens, $outputTokens);
    }

    public static function zero(): self
    {
        return new self(0, 0);
    }

    public function inputTokens(): int
    {
        return $this->inputTokens;
    }

    public function outputTokens(): int
    {
        return $this->outputTokens;
    }

    public function totalTokens(): int
    {
        return $this->inputTokens + $this->outputTokens;
    }
}
