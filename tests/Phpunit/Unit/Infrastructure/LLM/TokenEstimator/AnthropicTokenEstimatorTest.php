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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\TokenEstimator;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\AnthropicTokenEstimator;

final class AnthropicTokenEstimatorTest extends TestCase
{
    #[DataProvider('supportedModelCases')]
    public function test_it_supports_claude_models(string $model): void
    {
        self::assertTrue((new AnthropicTokenEstimator())->supports($model));
    }

    /** @return iterable<string, array{string}> */
    public static function supportedModelCases(): iterable
    {
        yield 'claude opus' => ['claude-opus-4-7'];
        yield 'claude fable' => ['claude-fable-5'];
        yield 'claude mythos' => ['claude-mythos-5'];
        yield 'bedrock claude' => ['anthropic.claude-opus-4-8'];
        yield 'bedrock cross-region claude' => ['us.anthropic.claude-opus-4-8'];
    }

    public function test_it_does_not_support_a_non_claude_model(): void
    {
        self::assertFalse((new AnthropicTokenEstimator())->supports('gpt-4o'));
    }

    #[DataProvider('ratioCases')]
    public function test_it_applies_the_per_model_ratio(string $model, int $expected): void
    {
        self::assertSame($expected, (new AnthropicTokenEstimator())->estimateTokens(str_repeat('x', 100), $model));
    }

    /** @return iterable<string, array{string, int}> */
    public static function ratioCases(): iterable
    {
        yield 'standard claude uses the 3.5 ratio' => ['claude-opus-4-7', 29];
        yield 'creative fable uses the denser 2.7 ratio' => ['claude-fable-5', 38];
        yield 'creative mythos uses the denser 2.7 ratio' => ['claude-mythos-5', 38];
        yield 'bedrock creative fable uses the denser 2.7 ratio' => ['anthropic.claude-fable-5', 38];
    }
}
