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

    /** @var array<string, array{model: string, input_tokens: int, output_tokens: int, cache_read_tokens: int, cache_creation_tokens: int, estimated_cost_usd: float}> */
    private array $usageByModel = [];

    public function __construct(
        private readonly AuditBudget $auditBudget,
        private readonly CostCalculator $costCalculator,
    ) {}

    public function recordCall(LLMResponse $llmResponse): void
    {
        $costUsd = $this->costCalculator->costForCall(
            $llmResponse->inputTokens(),
            $llmResponse->outputTokens(),
            $llmResponse->model(),
            $llmResponse->cacheReadTokens(),
            $llmResponse->cacheCreationTokens(),
        );

        $this->tokensUsed += $llmResponse->totalTokens();
        $this->costUsdUsed += $costUsd;
        $this->accumulateModelUsage($llmResponse, $costUsd);
    }

    private function accumulateModelUsage(LLMResponse $llmResponse, float $costUsd): void
    {
        $model = $llmResponse->model();
        $existing = $this->usageByModel[$model] ?? ['input_tokens' => 0, 'output_tokens' => 0, 'cache_read_tokens' => 0, 'cache_creation_tokens' => 0, 'estimated_cost_usd' => 0.0];

        $this->usageByModel[$model] = [
            'model' => $model,
            'input_tokens' => $existing['input_tokens'] + $llmResponse->inputTokens(),
            'output_tokens' => $existing['output_tokens'] + $llmResponse->outputTokens(),
            'cache_read_tokens' => $existing['cache_read_tokens'] + $llmResponse->cacheReadTokens(),
            'cache_creation_tokens' => $existing['cache_creation_tokens'] + $llmResponse->cacheCreationTokens(),
            'estimated_cost_usd' => $existing['estimated_cost_usd'] + $costUsd,
        ];
    }

    /**
     * Per-model totals for the run, so a report can tell a model that priced
     * to zero because it is unlisted from one that simply went unused. The
     * aggregate cannot: a priced attacker paired with an unpriced reviewer
     * still sums to a nonzero total.
     *
     * @return array<string, array{model: string, input_tokens: int, output_tokens: int, cache_read_tokens: int, cache_creation_tokens: int, estimated_cost_usd: float}>
     */
    public function usageByModel(): array
    {
        return $this->usageByModel;
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
        $this->usageByModel = [];
    }
}
