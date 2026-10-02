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
 * Opt-in extension of {@see PricingProviderInterface} for providers that know
 * the platform the audit runs against. The model a provider reports answering
 * a call is billed as that model only when the serving platform's own rate
 * applies to it, and as the configured model otherwise, so another provider
 * re-listing the same id at its own price never sets the bill. Consumers
 * check `instanceof ServingPlatformPricingProviderInterface` and fall back to
 * {@see PricingProviderInterface::hasModel()} when it is not implemented, so
 * adding this capability never breaks an existing provider.
 */
interface ServingPlatformPricingProviderInterface extends PricingProviderInterface
{
    /**
     * Whether the serving platform's own listing prices the model — or, for a
     * platform with no listing of its own, whether the model is priced at
     * all, since any other listing is then the only rate there is.
     */
    public function hasServingPlatformPrice(string $model): bool;
}
