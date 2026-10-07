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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

final readonly class FixedPricingProvider implements PricingProviderInterface
{
    public function __construct(
        private float $inputPrice,
        private float $outputPrice,
    ) {}

    #[Override]
    public function pricePerMillionInputTokens(string $model): float
    {
        return $this->inputPrice;
    }

    #[Override]
    public function pricePerMillionOutputTokens(string $model): float
    {
        return $this->outputPrice;
    }

    #[Override]
    public function hasModel(string $model): bool
    {
        return true;
    }
}
