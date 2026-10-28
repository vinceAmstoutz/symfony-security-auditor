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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Pricing;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricedModelList;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;

final class ModelsDevPricedModelListTest extends TestCase
{
    public function test_it_offers_a_model_named_by_digits_as_text(): void
    {
        $modelsDevPricedModelList = new ModelsDevPricedModelList(new ModelsDevPricingProvider(new NullLogger(), __DIR__.'/Fixture/numeric-model-id.json'));

        self::assertSame(['42'], $modelsDevPricedModelList->pricedModels('openai'));
    }
}
