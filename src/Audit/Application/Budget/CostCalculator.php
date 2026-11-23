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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ServingPlatformPricingProviderInterface;

use function Symfony\Component\String\u;

/**
 * Converts token counts to an unrounded USD cost. Prices prompt-cache traffic
 * at the provider's cache rates when it implements
 * {@see CacheAwarePricingProviderInterface}; otherwise at 0.1x read and 1.25x
 * write for Claude models and at the base input rate for others.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CostCalculator
{
    private const int TOKENS_PER_MILLION = 1_000_000;

    private const float ANTHROPIC_CACHE_READ_PRICE_MULTIPLIER = 0.1;

    private const float ANTHROPIC_CACHE_CREATION_PRICE_MULTIPLIER = 1.25;

    private const float ANTHROPIC_ONE_HOUR_CACHE_CREATION_PRICE_MULTIPLIER = 2.0;

    private const float PLAIN_INPUT_PRICE_MULTIPLIER = 1.0;

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

    /**
     * Prices one-hour prompt-cache writes at twice the base input rate, as
     * Anthropic bills them; pricing sources list only the five-minute rate.
     */
    public function costForOneHourCacheWrites(int $oneHourCacheCreationTokens, string $model): float
    {
        return ($oneHourCacheCreationTokens / self::TOKENS_PER_MILLION) * $this->pricingProvider->pricePerMillionInputTokens($model) * self::ANTHROPIC_ONE_HOUR_CACHE_CREATION_PRICE_MULTIPLIER;
    }

    /**
     * Returns the model the provider reports serving the call when the pricing
     * source prices it at the serving platform's own rate, the configured one
     * otherwise.
     */
    public function billedModel(string $configuredModel, ?string $reportedModel): string
    {
        return null !== $reportedModel && $this->pricesReportedModel($reportedModel) ? $reportedModel : $configuredModel;
    }

    private function pricesReportedModel(string $reportedModel): bool
    {
        return $this->pricingProvider instanceof ServingPlatformPricingProviderInterface
            ? $this->pricingProvider->hasServingPlatformPrice($reportedModel)
            : $this->pricingProvider->hasModel($reportedModel);
    }

    private function cacheReadPrice(string $model): float
    {
        if ($this->pricingProvider instanceof CacheAwarePricingProviderInterface) {
            return $this->pricingProvider->cacheReadPricePerMillionTokens($model);
        }

        return $this->pricingProvider->pricePerMillionInputTokens($model)
            * ($this->isClaudeModel($model) ? self::ANTHROPIC_CACHE_READ_PRICE_MULTIPLIER : self::PLAIN_INPUT_PRICE_MULTIPLIER);
    }

    private function cacheCreationPrice(string $model): float
    {
        if ($this->pricingProvider instanceof CacheAwarePricingProviderInterface) {
            return $this->pricingProvider->cacheCreationPricePerMillionTokens($model);
        }

        return $this->pricingProvider->pricePerMillionInputTokens($model)
            * ($this->isClaudeModel($model) ? self::ANTHROPIC_CACHE_CREATION_PRICE_MULTIPLIER : self::PLAIN_INPUT_PRICE_MULTIPLIER);
    }

    private function isClaudeModel(string $model): bool
    {
        return u($model)->containsAny('claude');
    }
}
