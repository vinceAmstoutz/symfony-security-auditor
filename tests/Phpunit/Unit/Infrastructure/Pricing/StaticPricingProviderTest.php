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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\StaticPricingProvider;

final class StaticPricingProviderTest extends TestCase
{
    #[DataProvider('knownModelCases')]
    public function test_it_returns_prices_for_known_models(string $model, float $inputPrice, float $outputPrice): void
    {
        $staticPricingProvider = new StaticPricingProvider(new NullLogger());

        self::assertTrue($staticPricingProvider->hasModel($model));
        self::assertSame($inputPrice, $staticPricingProvider->pricePerMillionInputTokens($model));
        self::assertSame($outputPrice, $staticPricingProvider->pricePerMillionOutputTokens($model));
    }

    /** @return iterable<string, array{string, float, float}> */
    public static function knownModelCases(): iterable
    {
        yield 'claude-opus-4-5' => ['claude-opus-4-5', 15.00, 75.00];
        yield 'claude-sonnet-4-5' => ['claude-sonnet-4-5', 3.00, 15.00];
        yield 'claude-haiku-4-5' => ['claude-haiku-4-5', 0.80, 4.00];
        yield 'gpt-4o' => ['gpt-4o', 2.50, 10.00];
        yield 'gpt-4o-mini' => ['gpt-4o-mini', 0.15, 0.60];
        yield 'gemini-2.5-pro' => ['gemini-2.5-pro', 1.25, 10.00];
    }

    public function test_unknown_model_returns_zero_input_price(): void
    {
        $staticPricingProvider = new StaticPricingProvider(new NullLogger());

        self::assertFalse($staticPricingProvider->hasModel('unknown-model'));
        self::assertSame(0.0, $staticPricingProvider->pricePerMillionInputTokens('unknown-model'));
        self::assertSame(0.0, $staticPricingProvider->pricePerMillionOutputTokens('unknown-model'));
    }

    public function test_unknown_model_is_warned_once(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $staticPricingProvider = new StaticPricingProvider($logger);
        $staticPricingProvider->pricePerMillionInputTokens('mystery-3');
        $staticPricingProvider->pricePerMillionOutputTokens('mystery-3');
        $staticPricingProvider->pricePerMillionInputTokens('mystery-3');

        self::assertCount(1, $warnings);
        self::assertSame('No pricing entry for LLM model — cost reporting will show zero', $warnings[0][0]);
        self::assertSame(['model' => 'mystery-3'], $warnings[0][1]);
    }
}
