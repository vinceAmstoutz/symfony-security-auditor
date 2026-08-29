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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AnthropicOptionDialect;

final class AnthropicOptionDialectTest extends TestCase
{
    #[DataProvider('honoredModels')]
    public function test_an_anthropic_dialect_model_honors_the_option_set(string $model): void
    {
        self::assertTrue(AnthropicOptionDialect::honoredBy($model));
    }

    #[DataProvider('unhonoredModels')]
    public function test_any_other_model_does_not(string $model): void
    {
        self::assertFalse(AnthropicOptionDialect::honoredBy($model));
    }

    /** @return iterable<string, array{string}> */
    public static function honoredModels(): iterable
    {
        yield 'anthropic api' => ['claude-opus-5'];
        yield 'vertex' => ['claude-opus-5@20260101'];
        yield 'vertex dotted' => ['claude.opus.5'];
        yield 'bedrock' => ['anthropic.claude-opus-5-v1:0'];
        yield 'bedrock us cross-region' => ['us.anthropic.claude-opus-5-v1:0'];
        yield 'bedrock eu cross-region' => ['eu.anthropic.claude-opus-5-v1:0'];
        yield 'bedrock au cross-region' => ['au.anthropic.claude-opus-5-v1:0'];
        yield 'bedrock jp cross-region' => ['jp.anthropic.claude-opus-5-v1:0'];
        yield 'bedrock global cross-region' => ['global.anthropic.claude-opus-5-v1:0'];
        yield 'bedrock a future cross-region prefix' => ['xx.anthropic.claude-opus-5-v1:0'];
        yield 'provider-qualified gateway id' => ['anthropic/claude-opus-5'];
        yield 'nested gateway id' => ['openrouter/anthropic/claude-opus-5'];
        yield 'vertex publisher path' => ['publishers/anthropic/models/claude-opus-5'];
        yield 'model options query string' => ['claude-opus-5?temperature=0.2'];
        yield 'option value containing a slash' => ['claude-opus-5?base_url=https://gw.example/v1'];
        yield 'gateway id with options' => ['anthropic/claude-opus-5?temperature=0.2'];
    }

    /** @return iterable<string, array{string}> */
    public static function unhonoredModels(): iterable
    {
        yield 'openai' => ['gpt-4o'];
        yield 'gemini' => ['gemini-2.5-pro'];
        yield 'mistral' => ['mistral-large-latest'];
        yield 'gateway alias hiding its origin' => ['acme-gateway/fast'];
        yield 'unrelated model merely containing claude' => ['openrouter/not-claude-at-all'];
        yield 'vendor segment without a claude family segment' => ['anthropic.gpt-4o'];
        yield 'claude segment not preceded by the vendor segment' => ['acme.notclaude'];
        yield 'empty' => [''];
    }
}
