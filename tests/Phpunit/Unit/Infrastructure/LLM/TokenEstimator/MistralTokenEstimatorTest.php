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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\MistralTokenEstimator;

final class MistralTokenEstimatorTest extends TestCase
{
    #[DataProvider('supportedModelCases')]
    public function test_it_supports_mistral_models(string $model): void
    {
        self::assertTrue((new MistralTokenEstimator())->supports($model));
    }

    /** @return iterable<string, array{string}> */
    public static function supportedModelCases(): iterable
    {
        yield 'mistral prefix' => ['mistral-large-2'];
        yield 'codestral prefix' => ['codestral-25.01'];
        yield 'devstral prefix' => ['devstral-medium-latest'];
        yield 'magistral prefix' => ['magistral-medium-latest'];
        yield 'ministral prefix' => ['ministral-8b-latest'];
        yield 'open-mistral prefix' => ['open-mistral-7b'];
        yield 'open-mixtral prefix' => ['open-mixtral-8x22b'];
        yield 'pixtral prefix' => ['pixtral-large-latest'];
    }

    public function test_it_does_not_support_a_non_mistral_model(): void
    {
        self::assertFalse((new MistralTokenEstimator())->supports('gpt-4o'));
    }

    public function test_it_applies_the_mistral_ratio(): void
    {
        self::assertSame(28, (new MistralTokenEstimator())->estimateTokens(str_repeat('x', 100), 'mistral-large-2'));
    }
}
