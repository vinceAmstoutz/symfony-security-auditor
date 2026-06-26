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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\Pricing;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;

final class ModelsDevPricingProviderIntegrationTest extends TestCase
{
    public function test_it_resolves_the_installed_symfony_models_dev_catalog_by_default(): void
    {
        $modelsDevPricingProvider = new ModelsDevPricingProvider(new NullLogger());

        self::assertTrue(
            $modelsDevPricingProvider->hasModel('claude-opus-4-8'),
            'The default model must be priced from the installed symfony/models-dev catalog.',
        );
        self::assertGreaterThan(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8'));
        self::assertGreaterThan(0.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('claude-opus-4-8'));
        self::assertGreaterThan(0.0, $modelsDevPricingProvider->cacheReadPricePerMillionTokens('claude-opus-4-8'));
    }
}
