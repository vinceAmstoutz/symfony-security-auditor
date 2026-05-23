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
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CostCalculator
{
    private const int TOKENS_PER_MILLION = 1_000_000;

    public function __construct(private PricingProviderInterface $pricingProvider) {}

    public function costForCall(int $inputTokens, int $outputTokens, string $model): float
    {
        $inputCost = ($inputTokens / self::TOKENS_PER_MILLION) * $this->pricingProvider->pricePerMillionInputTokens($model);
        $outputCost = ($outputTokens / self::TOKENS_PER_MILLION) * $this->pricingProvider->pricePerMillionOutputTokens($model);

        return round($inputCost + $outputCost, 6);
    }
}
