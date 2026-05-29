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
        // Anthropic Claude — current
        yield 'claude-opus-4-8' => ['claude-opus-4-8', 5.00, 25.00];
        yield 'claude-sonnet-4-6' => ['claude-sonnet-4-6', 3.00, 15.00];
        yield 'claude-haiku-4-5-20251001' => ['claude-haiku-4-5-20251001', 1.00, 5.00];
        // Anthropic Claude — legacy
        yield 'claude-haiku-4-5' => ['claude-haiku-4-5', 1.00, 5.00];
        yield 'claude-opus-4-7' => ['claude-opus-4-7', 5.00, 25.00];
        yield 'claude-opus-4-6' => ['claude-opus-4-6', 5.00, 25.00];
        yield 'claude-opus-4-5-20251101' => ['claude-opus-4-5-20251101', 5.00, 25.00];
        yield 'claude-opus-4-5' => ['claude-opus-4-5', 5.00, 25.00];
        yield 'claude-sonnet-4-5-20250929' => ['claude-sonnet-4-5-20250929', 3.00, 15.00];
        yield 'claude-sonnet-4-5' => ['claude-sonnet-4-5', 3.00, 15.00];
        yield 'claude-opus-4-1-20250805' => ['claude-opus-4-1-20250805', 15.00, 75.00];
        yield 'claude-opus-4-1' => ['claude-opus-4-1', 15.00, 75.00];
        yield 'claude-opus-4-20250514' => ['claude-opus-4-20250514', 15.00, 75.00];
        yield 'claude-opus-4' => ['claude-opus-4', 15.00, 75.00];
        yield 'claude-opus-4-0' => ['claude-opus-4-0', 15.00, 75.00];
        yield 'claude-sonnet-4-20250514' => ['claude-sonnet-4-20250514', 3.00, 15.00];
        yield 'claude-sonnet-4' => ['claude-sonnet-4', 3.00, 15.00];
        yield 'claude-sonnet-4-0' => ['claude-sonnet-4-0', 3.00, 15.00];
        // OpenAI
        yield 'gpt-5.5-pro' => ['gpt-5.5-pro', 30.00, 180.00];
        yield 'gpt-5.5' => ['gpt-5.5', 5.00, 30.00];
        yield 'gpt-5.4-pro' => ['gpt-5.4-pro', 30.00, 180.00];
        yield 'gpt-5.4' => ['gpt-5.4', 2.50, 15.00];
        yield 'gpt-5.4-mini' => ['gpt-5.4-mini', 0.75, 4.50];
        yield 'gpt-5.4-nano' => ['gpt-5.4-nano', 0.20, 1.25];
        yield 'gpt-5-mini' => ['gpt-5-mini', 0.25, 2.00];
        yield 'gpt-5-nano' => ['gpt-5-nano', 0.05, 0.40];
        yield 'gpt-4.1' => ['gpt-4.1', 2.00, 8.00];
        yield 'gpt-4.1-mini' => ['gpt-4.1-mini', 0.40, 1.60];
        yield 'gpt-4.1-nano' => ['gpt-4.1-nano', 0.10, 0.40];
        yield 'gpt-4o' => ['gpt-4o', 2.50, 10.00];
        yield 'gpt-4o-mini' => ['gpt-4o-mini', 0.15, 0.60];
        yield 'o3' => ['o3', 2.00, 8.00];
        yield 'o4-mini' => ['o4-mini', 0.55, 2.20];
        // Google Gemini
        yield 'gemini-3.5-flash' => ['gemini-3.5-flash', 1.50, 9.00];
        yield 'gemini-3.1-pro-preview' => ['gemini-3.1-pro-preview', 2.00, 12.00];
        yield 'gemini-3.1-flash-lite' => ['gemini-3.1-flash-lite', 0.25, 1.50];
        yield 'gemini-3-flash-preview' => ['gemini-3-flash-preview', 0.50, 3.00];
        yield 'gemini-2.5-pro' => ['gemini-2.5-pro', 1.25, 10.00];
        yield 'gemini-2.5-flash' => ['gemini-2.5-flash', 0.30, 2.50];
        yield 'gemini-2.5-flash-lite' => ['gemini-2.5-flash-lite', 0.10, 0.40];
        yield 'gemini-2.0-flash' => ['gemini-2.0-flash', 0.10, 0.40];
        // Mistral AI
        yield 'mistral-large-latest' => ['mistral-large-latest', 0.50, 1.50];
        yield 'mistral-large-2512' => ['mistral-large-2512', 0.50, 1.50];
        yield 'mistral-medium-latest' => ['mistral-medium-latest', 1.50, 7.50];
        yield 'mistral-medium-2604' => ['mistral-medium-2604', 1.50, 7.50];
        yield 'mistral-small-latest' => ['mistral-small-latest', 0.15, 0.60];
        yield 'mistral-small-2603' => ['mistral-small-2603', 0.15, 0.60];
        yield 'codestral-latest' => ['codestral-latest', 0.30, 0.90];
        yield 'codestral-2508' => ['codestral-2508', 0.30, 0.90];
        yield 'devstral-medium-2512' => ['devstral-medium-2512', 0.40, 2.00];
        yield 'devstral-small-2512' => ['devstral-small-2512', 0.10, 0.30];
        yield 'ministral-3b-2512' => ['ministral-3b-2512', 0.10, 0.10];
        yield 'ministral-8b-2512' => ['ministral-8b-2512', 0.15, 0.15];
        yield 'ministral-14b-2512' => ['ministral-14b-2512', 0.20, 0.20];
        // Cohere
        yield 'command-a-03-2025' => ['command-a-03-2025', 2.50, 10.00];
        yield 'command-r-plus-08-2024' => ['command-r-plus-08-2024', 2.50, 10.00];
        yield 'command-r-08-2024' => ['command-r-08-2024', 0.15, 0.60];
        yield 'command-r7b-12-2024' => ['command-r7b-12-2024', 0.0375, 0.15];
        // DeepSeek
        yield 'deepseek-chat' => ['deepseek-chat', 0.14, 0.28];
        yield 'deepseek-reasoner' => ['deepseek-reasoner', 0.14, 0.28];
        yield 'deepseek-v4-flash' => ['deepseek-v4-flash', 0.14, 0.28];
        yield 'deepseek-v4-pro' => ['deepseek-v4-pro', 1.74, 3.48];
        // Perplexity
        yield 'sonar' => ['sonar', 1.00, 1.00];
        yield 'sonar-pro' => ['sonar-pro', 3.00, 15.00];
        yield 'sonar-reasoning-pro' => ['sonar-reasoning-pro', 2.00, 8.00];
        // Cerebras
        yield 'gpt-oss-120b' => ['gpt-oss-120b', 0.35, 0.75];
        yield 'zai-glm-4.7' => ['zai-glm-4.7', 2.25, 2.75];
    }

    public function test_unknown_model_returns_zero_input_price(): void
    {
        $staticPricingProvider = new StaticPricingProvider(new NullLogger());

        self::assertFalse($staticPricingProvider->hasModel('unknown-model'));
        self::assertSame(0.0, $staticPricingProvider->pricePerMillionInputTokens('unknown-model'));
        self::assertSame(0.0, $staticPricingProvider->pricePerMillionOutputTokens('unknown-model'));
    }

    public function test_unknown_model_is_warned_once_when_queried_multiple_times(): void
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

    public function test_input_price_query_warns_when_model_is_unknown(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $staticPricingProvider = new StaticPricingProvider($logger);
        $staticPricingProvider->pricePerMillionInputTokens('mystery-input');

        self::assertCount(1, $warnings);
        self::assertSame(['model' => 'mystery-input'], $warnings[0][1]);
    }

    public function test_output_price_query_warns_when_model_is_unknown(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $staticPricingProvider = new StaticPricingProvider($logger);
        $staticPricingProvider->pricePerMillionOutputTokens('mystery-output');

        self::assertCount(1, $warnings);
        self::assertSame(['model' => 'mystery-output'], $warnings[0][1]);
    }
}
