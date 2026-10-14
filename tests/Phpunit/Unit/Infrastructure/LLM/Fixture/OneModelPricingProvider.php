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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

/**
 * Test fake: a pricing catalog that prices `priced-model` alone.
 */
final readonly class OneModelPricingProvider implements PricingProviderInterface
{
    public const string PRICED_MODEL = 'priced-model';

    #[Override]
    public function pricePerMillionInputTokens(string $model): float
    {
        return $this->hasModel($model) ? 1.0 : 0.0;
    }

    #[Override]
    public function pricePerMillionOutputTokens(string $model): float
    {
        return $this->hasModel($model) ? 1.0 : 0.0;
    }

    #[Override]
    public function hasModel(string $model): bool
    {
        return self::PRICED_MODEL === $model;
    }
}
