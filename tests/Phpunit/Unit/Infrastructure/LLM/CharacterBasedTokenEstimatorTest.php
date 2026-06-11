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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CharacterBasedTokenEstimator;

final class CharacterBasedTokenEstimatorTest extends TestCase
{
    public function test_empty_string_returns_zero_tokens(): void
    {
        $characterBasedTokenEstimator = new CharacterBasedTokenEstimator();

        self::assertSame(0, $characterBasedTokenEstimator->estimateTokens('', 'claude-opus-4-7'));
    }

    public function test_multibyte_characters_are_counted_as_one_each_via_mb_strlen(): void
    {
        $characterBasedTokenEstimator = new CharacterBasedTokenEstimator();

        // U+20AC = 3 bytes in UTF-8: mb_strlen('€'×10) = 10, strlen = 30. Pins mb_strlen vs strlen.
        self::assertSame(3, $characterBasedTokenEstimator->estimateTokens(str_repeat('€', 10), 'claude-opus-4-7'));
    }

    public function test_estimate_uses_ceiling_so_fractional_tokens_round_up(): void
    {
        $characterBasedTokenEstimator = new CharacterBasedTokenEstimator();

        // 8 / 3.5 = 2.285 → ceil=3, round=2, floor=2. Pins ceil against round/floor.
        self::assertSame(3, $characterBasedTokenEstimator->estimateTokens(str_repeat('x', 8), 'claude-opus-4-7'));
    }

    #[DataProvider('modelDivisorCases')]
    public function test_estimate_uses_per_model_divisor(string $model, int $expected): void
    {
        $characterBasedTokenEstimator = new CharacterBasedTokenEstimator();

        self::assertSame($expected, $characterBasedTokenEstimator->estimateTokens(str_repeat('x', 100), $model));
    }

    /** @return iterable<string, array{string, int}> */
    public static function modelDivisorCases(): iterable
    {
        yield 'claude_uses_claude_divisor' => ['claude-opus-4-7', 29];
        yield 'claude_fable_uses_denser_fable_divisor' => ['claude-fable-5', 38];
        yield 'claude_mythos_uses_denser_fable_divisor' => ['claude-mythos-5', 38];
        yield 'gpt_uses_gpt_divisor' => ['gpt-4o', 25];
        yield 'o3_uses_gpt_divisor' => ['o3', 25];
        yield 'o4_uses_gpt_divisor' => ['o4-mini', 25];
        yield 'gemini_uses_gemini_divisor' => ['gemini-2.5-pro', 27];
        yield 'mistral_uses_mistral_divisor' => ['mistral-large-2', 28];
        yield 'codestral_uses_mistral_divisor' => ['codestral-25.01', 28];
        yield 'llama_dashed_uses_llama_divisor' => ['llama-3.3-70b', 28];
        yield 'llama3_concat_uses_llama_divisor' => ['llama3', 28];
        yield 'meta_llama_uses_llama_divisor' => ['meta-llama/Llama-3.3-70B-Instruct', 28];
        yield 'deepseek_uses_deepseek_divisor' => ['deepseek-chat', 30];
        yield 'unknown_model_uses_default_divisor' => ['mystery-7', 32];
    }

    public function test_user_provided_prefix_overrides_built_in_ratio(): void
    {
        $characterBasedTokenEstimator = new CharacterBasedTokenEstimator(['claude-' => 2.0]);

        // 100 chars / 2.0 = 50 tokens; default Claude ratio (3.5) would yield 29.
        self::assertSame(50, $characterBasedTokenEstimator->estimateTokens(str_repeat('x', 100), 'claude-opus-4-7'));
    }

    public function test_user_provided_prefix_falls_through_to_defaults_when_model_does_not_match(): void
    {
        $characterBasedTokenEstimator = new CharacterBasedTokenEstimator(['my-custom-' => 2.0]);

        // GPT default 4.0 still applies for 'gpt-4o'.
        self::assertSame(25, $characterBasedTokenEstimator->estimateTokens(str_repeat('x', 100), 'gpt-4o'));
    }

    public function test_longer_text_yields_strictly_more_tokens(): void
    {
        $characterBasedTokenEstimator = new CharacterBasedTokenEstimator();

        $short = $characterBasedTokenEstimator->estimateTokens(str_repeat('a', 1_000), 'claude-opus-4-7');
        $long = $characterBasedTokenEstimator->estimateTokens(str_repeat('a', 10_000), 'claude-opus-4-7');

        self::assertGreaterThan($short, $long);
        self::assertEqualsWithDelta(10 * $short, $long, 5);
    }
}
