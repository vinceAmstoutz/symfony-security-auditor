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
 * `instanceof`: knows the serving platform, so a reported model is billed as
 * itself only when that platform's own rate applies to it, else as the
 * configured model. Without it, {@see PricingProviderInterface::hasModel()}
 * decides.
 */
interface ServingPlatformPricingProviderInterface extends PricingProviderInterface
{
    /**
     * Whether the serving platform's own listing prices the model or, for a
     * platform with no listing of its own, whether any listing does.
     */
    public function hasServingPlatformPrice(string $model): bool;
}
