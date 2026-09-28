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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BedrockMantleRoute;

final class BedrockMantleRouteTest extends TestCase
{
    #[DataProvider('routeCases')]
    public function test_it_picks_the_mantle_route_serving_the_model(string $model, string $expectedRoute, ?string $expectedCompanionPlatform): void
    {
        self::assertSame($expectedRoute, BedrockMantleRoute::of($model));
        self::assertSame($expectedCompanionPlatform, BedrockMantleRoute::companionPlatform($model));
    }

    /**
     * @return iterable<string, array{string, string, string|null}>
     */
    public static function routeCases(): iterable
    {
        yield 'an anthropic model speaks the messages api' => ['anthropic.claude-opus-4-8', 'messages', null];
        yield 'gemma speaks the responses api' => ['google.gemma-4-31b', 'responses', 'openresponses'];
        yield 'gpt-oss speaks chat completions' => ['openai.gpt-oss-120b', 'completions', 'generic'];
        yield 'qwen speaks chat completions' => ['qwen.qwen3-32b', 'completions', 'generic'];
    }

    #[DataProvider('vendorCases')]
    public function test_it_tells_a_model_named_after_its_vendor(string $model, bool $expected): void
    {
        self::assertSame($expected, BedrockMantleRoute::namesAVendor($model));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function vendorCases(): iterable
    {
        yield 'a vendor-prefixed id' => ['anthropic.claude-opus-4-8', true];
        yield 'a bare id' => ['claude-opus-4-8', false];
        yield 'a dotted version that names no vendor' => ['gpt-4.1', false];
        yield 'a vendor further into the id' => ['my.anthropic.claude', true];
        yield 'a prefix buried after text' => ['x-anthropic.claude', false];
    }

    #[DataProvider('platformCases')]
    public function test_it_applies_to_bedrock_only(string $provider, bool $expected): void
    {
        self::assertSame($expected, BedrockMantleRoute::applies(ProviderKey::of($provider)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function platformCases(): iterable
    {
        yield 'a bedrock instance' => ['bedrock.prod', true];
        yield 'another platform' => ['anthropic', false];
    }
}
