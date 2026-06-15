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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\OpenAiTokenEstimator;

final class OpenAiTokenEstimatorTest extends TestCase
{
    #[DataProvider('supportedModelCases')]
    public function test_it_supports_openai_models(string $model): void
    {
        self::assertTrue((new OpenAiTokenEstimator())->supports($model));
    }

    /** @return iterable<string, array{string}> */
    public static function supportedModelCases(): iterable
    {
        yield 'gpt prefix' => ['gpt-4o'];
        yield 'o3 reasoning model' => ['o3'];
        yield 'o4 reasoning model' => ['o4-mini'];
    }

    public function test_it_does_not_support_a_non_openai_model(): void
    {
        self::assertFalse((new OpenAiTokenEstimator())->supports('claude-opus-4-7'));
    }

    public function test_it_applies_the_four_characters_per_token_ratio(): void
    {
        self::assertSame(25, (new OpenAiTokenEstimator())->estimateTokens(str_repeat('x', 100), 'gpt-4o'));
    }
}
