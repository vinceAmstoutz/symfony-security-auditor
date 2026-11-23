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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Port;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullPricingProvider;

final class NullPricingProviderTest extends TestCase
{
    public function test_it_prices_no_model_not_even_one_an_api_prices(): void
    {
        $nullPricingProvider = new NullPricingProvider();

        self::assertSame(
            [false, 0.0, 0.0],
            [$nullPricingProvider->hasModel('claude-opus-5-5'), $nullPricingProvider->pricePerMillionInputTokens('claude-opus-5-5'), $nullPricingProvider->pricePerMillionOutputTokens('claude-opus-5-5')],
        );
    }
}
