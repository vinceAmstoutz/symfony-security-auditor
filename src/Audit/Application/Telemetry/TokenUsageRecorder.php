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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;

/**
 * Accumulates LLM token usage across all calls within a single audit run.
 *
 * The recorder is the single source of truth for cumulative usage. Both the
 * attacker and reviewer LLM clients share one instance so the audit budget
 * can be enforced globally and the final report can attribute total cost.
 *
 * Mutable by design — `LLMClientInterface` callers report each call's deltas
 * via {@see record()}; the orchestrator and budget tracker read totals via
 * {@see snapshot()}. {@see reset()} clears state between independent audit
 * runs sharing a recorder instance.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class TokenUsageRecorder
{
    private int $inputTokens = 0;

    private int $outputTokens = 0;

    private int $cacheReadTokens = 0;

    private int $cacheCreationTokens = 0;

    /**
     * @throws NegativeTokenCountException
     */
    public function record(int $inputTokens, int $outputTokens, int $cacheReadTokens = 0, int $cacheCreationTokens = 0): void
    {
        if ($inputTokens < 0) {
            throw NegativeTokenCountException::forInputTokens($inputTokens);
        }

        if ($outputTokens < 0) {
            throw NegativeTokenCountException::forOutputTokens($outputTokens);
        }

        if ($cacheReadTokens < 0) {
            throw NegativeTokenCountException::forCacheReadTokens($cacheReadTokens);
        }

        if ($cacheCreationTokens < 0) {
            throw NegativeTokenCountException::forCacheCreationTokens($cacheCreationTokens);
        }

        $this->inputTokens += $inputTokens;
        $this->outputTokens += $outputTokens;
        $this->cacheReadTokens += $cacheReadTokens;
        $this->cacheCreationTokens += $cacheCreationTokens;
    }

    public function snapshot(): TokenUsageSnapshot
    {
        return TokenUsageSnapshot::of($this->inputTokens, $this->outputTokens, $this->cacheReadTokens, $this->cacheCreationTokens);
    }

    public function reset(): void
    {
        $this->inputTokens = 0;
        $this->outputTokens = 0;
        $this->cacheReadTokens = 0;
        $this->cacheCreationTokens = 0;
    }
}
