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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;

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
        private int $cacheReadTokens,
        private int $cacheCreationTokens,
    ) {}

    /**
     * @throws InvalidTokenUsageException
     */
    public static function of(int $inputTokens, int $outputTokens, int $cacheReadTokens = 0, int $cacheCreationTokens = 0): self
    {
        if ($inputTokens < 0) {
            throw InvalidTokenUsageException::forNegativeInputTokens($inputTokens);
        }

        if ($outputTokens < 0) {
            throw InvalidTokenUsageException::forNegativeOutputTokens($outputTokens);
        }

        if ($cacheReadTokens < 0) {
            throw InvalidTokenUsageException::forNegativeCacheReadTokens($cacheReadTokens);
        }

        if ($cacheCreationTokens < 0) {
            throw InvalidTokenUsageException::forNegativeCacheCreationTokens($cacheCreationTokens);
        }

        return new self($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens);
    }

    public static function zero(): self
    {
        return new self(0, 0, 0, 0);
    }

    public function inputTokens(): int
    {
        return $this->inputTokens;
    }

    public function outputTokens(): int
    {
        return $this->outputTokens;
    }

    public function cacheReadTokens(): int
    {
        return $this->cacheReadTokens;
    }

    public function cacheCreationTokens(): int
    {
        return $this->cacheCreationTokens;
    }

    public function totalTokens(): int
    {
        return $this->inputTokens + $this->outputTokens;
    }
}
