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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * Tracks cumulative token and cost usage against an `AuditBudget`.
 *
 * The LLM client calls `recordCall()` after every successful platform call,
 * then `assertWithinBudget()` to abort the run if the configured cap is now
 * exceeded. The call that exceeds the cap still completes (its tokens are
 * recorded); the next call is what gets refused — predictable for users
 * reasoning about partial reports.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class BudgetTracker
{
    private int $tokensUsed = 0;

    private float $costUsdUsed = 0.0;

    public function __construct(
        private readonly AuditBudget $auditBudget,
        private readonly CostCalculator $costCalculator,
    ) {}

    public function recordCall(LLMResponse $llmResponse): void
    {
        $this->tokensUsed += $llmResponse->totalTokens();
        $this->costUsdUsed += $this->costCalculator->costForCall(
            $llmResponse->inputTokens(),
            $llmResponse->outputTokens(),
            $llmResponse->model(),
            $llmResponse->cacheReadTokens(),
            $llmResponse->cacheCreationTokens(),
        );
    }

    /**
     * @throws BudgetExceededException
     */
    public function assertWithinBudget(): void
    {
        $maxTokens = $this->auditBudget->maxTokens();
        if (null !== $maxTokens && $this->tokensUsed > $maxTokens) {
            throw BudgetExceededException::forTokens($this->tokensUsed, $maxTokens);
        }

        $maxCostUsd = $this->auditBudget->maxCostUsd();
        $costUsdUsed = $this->costUsdUsed();
        if (null !== $maxCostUsd && $costUsdUsed > round($maxCostUsd, 6)) {
            throw BudgetExceededException::forCost($costUsdUsed, $maxCostUsd);
        }
    }

    public function tokensUsed(): int
    {
        return $this->tokensUsed;
    }

    public function costUsdUsed(): float
    {
        return round($this->costUsdUsed, 6);
    }

    public function reset(): void
    {
        $this->tokensUsed = 0;
        $this->costUsdUsed = 0.0;
    }
}
