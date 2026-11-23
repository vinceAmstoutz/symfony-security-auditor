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
 * Tracks cumulative token and cost usage against an `AuditBudget`. The call
 * that crosses the cap is still recorded; `assertWithinBudget()` then refuses
 * the next one.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class BudgetTracker
{
    private int $tokensUsed = 0;

    private float $costUsdUsed = 0.0;

    private int $interruptedCalls = 0;

    /** @var array<string, array{model: string, input_tokens: int, output_tokens: int, cache_read_tokens: int, cache_creation_tokens: int, estimated_cost_usd: float, billed_models: list<string>}> */
    private array $usageByModel = [];

    public function __construct(
        private readonly AuditBudget $auditBudget,
        private readonly CostCalculator $costCalculator,
    ) {}

    /**
     * `$oneHourCacheCreationTokens` is the share of the call's cache writes
     * the provider keeps for an hour, which it bills at its own rate.
     */
    public function recordCall(LLMResponse $llmResponse, int $oneHourCacheCreationTokens = 0): void
    {
        $billedModel = $this->costCalculator->billedModel($llmResponse->model(), $llmResponse->reportedModel());
        $costUsd = $this->costCalculator->costForCall(
            $llmResponse->inputTokens(),
            $llmResponse->outputTokens(),
            $billedModel,
            $llmResponse->cacheReadTokens(),
            $llmResponse->cacheCreationTokens() - $oneHourCacheCreationTokens,
        ) + $this->costCalculator->costForOneHourCacheWrites($oneHourCacheCreationTokens, $billedModel);

        $this->tokensUsed += $llmResponse->totalTokens();
        $this->costUsdUsed += $costUsd;
        $this->accumulateModelUsage($llmResponse, $billedModel, $costUsd);
    }

    private function accumulateModelUsage(LLMResponse $llmResponse, string $billedModel, float $costUsd): void
    {
        $model = $llmResponse->model();
        $existing = $this->usageByModel[$model] ?? ['input_tokens' => 0, 'output_tokens' => 0, 'cache_read_tokens' => 0, 'cache_creation_tokens' => 0, 'estimated_cost_usd' => 0.0, 'billed_models' => []];

        $this->usageByModel[$model] = [
            'model' => $model,
            'input_tokens' => $existing['input_tokens'] + $llmResponse->inputTokens(),
            'output_tokens' => $existing['output_tokens'] + $llmResponse->outputTokens(),
            'cache_read_tokens' => $existing['cache_read_tokens'] + $llmResponse->cacheReadTokens(),
            'cache_creation_tokens' => $existing['cache_creation_tokens'] + $llmResponse->cacheCreationTokens(),
            'estimated_cost_usd' => $existing['estimated_cost_usd'] + $costUsd,
            'billed_models' => \in_array($billedModel, $existing['billed_models'], true) ? $existing['billed_models'] : [...$existing['billed_models'], $billedModel],
        ];
    }

    /**
     * Returns the run's totals per configured model, each naming the models
     * its calls were billed as, in first-billed order.
     *
     * @return array<string, array{model: string, input_tokens: int, output_tokens: int, cache_read_tokens: int, cache_creation_tokens: int, estimated_cost_usd: float, billed_models: list<string>}>
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

    /**
     * Marks the booked cost as a minimum after a call cut before its answer
     * ended, which the provider may bill beyond the usage it reported.
     */
    public function recordInterruptedCall(): void
    {
        ++$this->interruptedCalls;
    }

    public function interruptedCalls(): int
    {
        return $this->interruptedCalls;
    }

    public function reset(): void
    {
        $this->tokensUsed = 0;
        $this->costUsdUsed = 0.0;
        $this->interruptedCalls = 0;
        $this->usageByModel = [];
    }
}
