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
 * Optional extension of {@see PricingProviderInterface}, checked with
 * `instanceof`: per-model prompt-cache rates. Without it, cache traffic is
 * priced at the base input rate.
 *
 * For an unpriced or cache-free model an implementation SHOULD return the base
 * input rate, so cache traffic is never priced below plain input.
 */
interface CacheAwarePricingProviderInterface extends PricingProviderInterface
{
    public function cacheReadPricePerMillionTokens(string $model): float;

    public function cacheCreationPricePerMillionTokens(string $model): float;
}
