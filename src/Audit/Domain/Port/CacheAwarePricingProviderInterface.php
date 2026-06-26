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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

/**
 * Opt-in extension of {@see PricingProviderInterface} for providers that
 * expose real per-model prompt-cache rates. Consumers check
 * `instanceof CacheAwarePricingProviderInterface` and fall back to pricing
 * cache traffic at the base input rate ({@see
 * PricingProviderInterface::pricePerMillionInputTokens()}) when it is not
 * implemented, so adding this capability never breaks an existing provider.
 *
 * Prompt caching is genuinely optional — not every provider bills it, and a
 * provider that does not should not be forced to stub these methods. For an
 * unpriced or cache-free model an implementation SHOULD return the base input
 * rate so cache traffic is never under-priced relative to plain input.
 */
interface CacheAwarePricingProviderInterface extends PricingProviderInterface
{
    public function cacheReadPricePerMillionTokens(string $model): float;

    public function cacheCreationPricePerMillionTokens(string $model): float;
}
