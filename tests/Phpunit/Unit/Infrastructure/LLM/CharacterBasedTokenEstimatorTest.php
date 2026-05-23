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

        self::assertSame(0, $characterBasedTokenEstimator->estimateTokens('', 'claude-opus-4-5'));
    }

    #[DataProvider('modelDivisorCases')]
    public function test_estimate_uses_per_model_divisor(string $model, int $expected): void
    {
        $characterBasedTokenEstimator = new CharacterBasedTokenEstimator();

        // 100 characters → tokens count depends on the model's chars-per-token constant.
        self::assertSame($expected, $characterBasedTokenEstimator->estimateTokens(str_repeat('x', 100), $model));
    }

    /** @return iterable<string, array{string, int}> */
    public static function modelDivisorCases(): iterable
    {
        // 100 / 3.5 = 28.57 → ceil → 29
        yield 'claude_uses_3.5_chars_per_token' => ['claude-opus-4-5', 29];
        yield 'gpt_uses_4.0_chars_per_token' => ['gpt-4o', 25];
        yield 'o3_uses_gpt_divisor' => ['o3', 25];
        yield 'gemini_uses_4.0_chars_per_token' => ['gemini-2.5-pro', 25];
        // Unknown model falls back to default (3.5)
        yield 'unknown_model_uses_default_divisor' => ['mystery-7', 29];
    }

    public function test_longer_text_yields_strictly_more_tokens(): void
    {
        $characterBasedTokenEstimator = new CharacterBasedTokenEstimator();

        $short = $characterBasedTokenEstimator->estimateTokens(str_repeat('a', 1_000), 'claude-opus-4-5');
        $long = $characterBasedTokenEstimator->estimateTokens(str_repeat('a', 10_000), 'claude-opus-4-5');

        // Ceiling makes the multiplier inexact; assert the order-of-magnitude relationship instead.
        self::assertGreaterThan($short, $long);
        self::assertEqualsWithDelta(10 * $short, $long, 5);
    }
}
