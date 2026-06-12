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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

/**
 * Converts token counts to USD cost using a pricing provider.
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

    // Anthropic prices cache reads at 0.1x and cache writes at 1.25x the base input rate.
    private const float CACHE_READ_PRICE_MULTIPLIER = 0.1;

    private const float CACHE_CREATION_PRICE_MULTIPLIER = 1.25;

    public function __construct(private PricingProviderInterface $pricingProvider) {}

    public function costForCall(
        int $inputTokens,
        int $outputTokens,
        string $model,
        int $cacheReadTokens = 0,
        int $cacheCreationTokens = 0,
    ): float {
        $inputPrice = $this->pricingProvider->pricePerMillionInputTokens($model);
        $inputCost = ($inputTokens / self::TOKENS_PER_MILLION) * $inputPrice;
        $outputCost = ($outputTokens / self::TOKENS_PER_MILLION) * $this->pricingProvider->pricePerMillionOutputTokens($model);
        $cacheReadCost = ($cacheReadTokens / self::TOKENS_PER_MILLION) * $inputPrice * self::CACHE_READ_PRICE_MULTIPLIER;
        $cacheCreationCost = ($cacheCreationTokens / self::TOKENS_PER_MILLION) * $inputPrice * self::CACHE_CREATION_PRICE_MULTIPLIER;

        return $inputCost + $outputCost + $cacheReadCost + $cacheCreationCost;
    }
}
