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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\CharacterRatioCounter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ProviderTokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;

final class ResolvingTokenEstimatorTest extends TestCase
{
    #[DataProvider('builtInRoutingCases')]
    public function test_it_routes_each_model_to_its_provider_ratio(string $model, int $expected): void
    {
        self::assertSame($expected, (new ResolvingTokenEstimator())->estimateTokens(str_repeat('x', 100), $model));
    }

    /** @return iterable<string, array{string, int}> */
    public static function builtInRoutingCases(): iterable
    {
        yield 'claude routes to anthropic' => ['claude-opus-4-7', 29];
        yield 'claude fable routes to anthropic creative ratio' => ['claude-fable-5', 38];
        yield 'claude mythos routes to anthropic creative ratio' => ['claude-mythos-5', 38];
        yield 'bedrock claude routes to anthropic' => ['anthropic.claude-opus-4-8', 29];
        yield 'bedrock cross-region claude routes to anthropic' => ['us.anthropic.claude-opus-4-8', 29];
        yield 'gpt routes to openai' => ['gpt-4o', 25];
        yield 'o3 routes to openai' => ['o3', 25];
        yield 'o4 routes to openai' => ['o4-mini', 25];
        yield 'gemini routes to gemini' => ['gemini-2.5-pro', 27];
        yield 'mistral routes to mistral' => ['mistral-large-2', 28];
        yield 'codestral routes to mistral' => ['codestral-25.01', 28];
        yield 'dashed llama routes to llama' => ['llama-3.3-70b', 28];
        yield 'concatenated llama routes to llama' => ['llama3', 28];
        yield 'meta-llama routes to llama' => ['meta-llama/Llama-3.3-70B-Instruct', 28];
        yield 'deepseek routes to deepseek' => ['deepseek-chat', 30];
        yield 'minimax routes to minimax' => ['MiniMax-M2', 29];
    }

    public function test_unknown_model_falls_back_to_the_default_ratio(): void
    {
        self::assertSame(32, (new ResolvingTokenEstimator())->estimateTokens(str_repeat('x', 100), 'mystery-7'));
    }

    public function test_fallback_ratio_is_configurable(): void
    {
        $resolvingTokenEstimator = new ResolvingTokenEstimator(
            providerEstimators: [],
            characterRatioCounter: new CharacterRatioCounter(),
            fallbackCharsPerToken: 2.0,
        );

        self::assertSame(50, $resolvingTokenEstimator->estimateTokens(str_repeat('x', 100), 'mystery-7'));
    }

    public function test_the_first_matching_provider_wins(): void
    {
        $resolvingTokenEstimator = new ResolvingTokenEstimator([
            $this->providerReturning(true, 11),
            $this->providerReturning(true, 22),
        ]);

        self::assertSame(11, $resolvingTokenEstimator->estimateTokens('anything', 'any-model'));
    }

    public function test_a_non_matching_provider_is_skipped_for_the_next_one(): void
    {
        $resolvingTokenEstimator = new ResolvingTokenEstimator([
            $this->providerReturning(false, 11),
            $this->providerReturning(true, 22),
        ]);

        self::assertSame(22, $resolvingTokenEstimator->estimateTokens('anything', 'any-model'));
    }

    private function providerReturning(bool $supports, int $tokens): ProviderTokenEstimatorInterface
    {
        return new class($supports, $tokens) implements ProviderTokenEstimatorInterface {
            public function __construct(private readonly bool $supports, private readonly int $tokens) {}

            #[Override]
            public function supports(string $model): bool
            {
                return $this->supports;
            }

            #[Override]
            public function estimateTokens(string $text, string $model): int
            {
                return $this->tokens;
            }
        };
    }
}
