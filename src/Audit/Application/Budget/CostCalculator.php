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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CacheAwarePricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

/**
 * Converts token counts to USD cost using a pricing provider.
 *
 * Prompt-cache traffic is priced from the provider's real per-model cache
 * rates when it implements {@see CacheAwarePricingProviderInterface};
 * otherwise it falls back to the base input rate.
 *
 * Returns the raw fractional cost — callers that present the value to a
 * user (`AuditCost`, `BudgetTracker::costUsdUsed()`) round to 6 decimals
 * at the surface. Keeping a single rounding site lets BudgetTracker test
 * its accessor against unrounded accumulated state.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CostCalculator
{
    private const int TOKENS_PER_MILLION = 1_000_000;

    public function __construct(private PricingProviderInterface $pricingProvider) {}

    public function costForCall(
        int $inputTokens,
        int $outputTokens,
        string $model,
        int $cacheReadTokens = 0,
        int $cacheCreationTokens = 0,
    ): float {
        $inputCost = ($inputTokens / self::TOKENS_PER_MILLION) * $this->pricingProvider->pricePerMillionInputTokens($model);
        $outputCost = ($outputTokens / self::TOKENS_PER_MILLION) * $this->pricingProvider->pricePerMillionOutputTokens($model);
        $cacheReadCost = ($cacheReadTokens / self::TOKENS_PER_MILLION) * $this->cacheReadPrice($model);
        $cacheCreationCost = ($cacheCreationTokens / self::TOKENS_PER_MILLION) * $this->cacheCreationPrice($model);

        return $inputCost + $outputCost + $cacheReadCost + $cacheCreationCost;
    }

    private function cacheReadPrice(string $model): float
    {
        return $this->pricingProvider instanceof CacheAwarePricingProviderInterface
            ? $this->pricingProvider->cacheReadPricePerMillionTokens($model)
            : $this->pricingProvider->pricePerMillionInputTokens($model);
    }

    private function cacheCreationPrice(string $model): float
    {
        return $this->pricingProvider instanceof CacheAwarePricingProviderInterface
            ? $this->pricingProvider->cacheCreationPricePerMillionTokens($model)
            : $this->pricingProvider->pricePerMillionInputTokens($model);
    }
}
