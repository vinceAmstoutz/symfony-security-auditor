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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\LlamaTokenEstimator;

final class LlamaTokenEstimatorTest extends TestCase
{
    #[DataProvider('supportedModelCases')]
    public function test_it_supports_llama_models(string $model): void
    {
        self::assertTrue((new LlamaTokenEstimator())->supports($model));
    }

    /** @return iterable<string, array{string}> */
    public static function supportedModelCases(): iterable
    {
        yield 'dashed llama' => ['llama-3.3-70b'];
        yield 'concatenated llama3' => ['llama3'];
        yield 'concatenated llama4' => ['llama4-scout'];
        yield 'meta-llama namespace' => ['meta-llama/Llama-3.3-70B-Instruct'];
        yield 'cerebras-hosted llama' => ['cerebras-llama-4-maverick-17b-128e-instruct'];
        yield 'groq-hosted llama' => ['groq-llama-4-maverick-17b-128e-instruct'];
        yield 'bedrock-hosted llama' => ['meta.llama3-1-70b-instruct-v1:0'];
        yield 'bedrock cross-region llama' => ['us.meta.llama4-scout-17b-instruct-v1:0'];
    }

    public function test_it_does_not_support_a_non_llama_model(): void
    {
        self::assertFalse((new LlamaTokenEstimator())->supports('gpt-4o'));
    }

    public function test_it_applies_the_llama_ratio(): void
    {
        self::assertSame(28, (new LlamaTokenEstimator())->estimateTokens(str_repeat('x', 100), 'llama3'));
    }
}
