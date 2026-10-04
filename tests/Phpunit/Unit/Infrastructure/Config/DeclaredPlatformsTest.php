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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\DeclaredPlatforms;

final class DeclaredPlatformsTest extends TestCase
{
    #[DataProvider('providers')]
    public function test_it_knows_which_platforms_the_bundle_declares(string $provider, bool $declared): void
    {
        self::assertSame($declared, DeclaredPlatforms::declares(ProviderKey::of($provider)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function providers(): iterable
    {
        yield 'a flat platform' => ['openai', true];
        yield 'an instance of an instance-keyed one' => ['generic.my_gateway', true];
        yield 'one the bundle dropped' => ['meta', false];
        yield 'a misspelling' => ['antropic', false];
    }

    public function test_init_offers_every_platform_it_takes_spelled_the_way_a_provider_names_it(): void
    {
        self::assertSame(
            [
                'albert', 'amazeeai', 'anthropic', 'azure.<instance>', 'bedrock.<instance>', 'cartesia', 'cerebras', 'cohere', 'decart',
                'deepgram', 'deepseek', 'dockermodelrunner', 'edenai', 'elevenlabs', 'fireworks', 'gemini', 'generic.<instance>',
                'higgsfield', 'huggingface', 'lmstudio', 'minimax', 'mistral', 'ollama', 'openai', 'openresponses.<instance>', 'openrouter',
                'ovh', 'perplexity', 'scaleway', 'together', 'transformersphp', 'typesafe', 'venice', 'vertexai', 'voyage',
            ],
            DeclaredPlatforms::initShapes(),
        );
    }
}
