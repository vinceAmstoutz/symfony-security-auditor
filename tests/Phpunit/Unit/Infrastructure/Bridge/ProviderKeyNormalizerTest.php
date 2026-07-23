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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Bridge;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKeyNormalizer;

final class ProviderKeyNormalizerTest extends TestCase
{
    #[DataProvider('providerSpellings')]
    public function test_it_folds_a_provider_spelling_to_the_platform_config_key(string $provider, string $expectedConfigKey): void
    {
        self::assertSame($expectedConfigKey, (new ProviderKeyNormalizer())->normalize($provider));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function providerSpellings(): iterable
    {
        yield 'config key kept as-is' => ['anthropic', 'anthropic'];
        yield 'unknown provider kept as-is' => ['my-ai', 'my-ai'];
        yield 'uppercase folded to the config key' => ['Anthropic', 'anthropic'];
        yield 'surrounding whitespace trimmed' => [' openai ', 'openai'];
        yield 'openai package slug' => ['open-ai', 'openai'];
        yield 'openresponses package slug' => ['open-responses', 'openresponses'];
        yield 'deepseek package slug' => ['deep-seek', 'deepseek'];
        yield 'vertexai package slug' => ['vertex-ai', 'vertexai'];
        yield 'huggingface package slug' => ['hugging-face', 'huggingface'];
        yield 'elevenlabs package slug' => ['eleven-labs', 'elevenlabs'];
        yield 'amazeeai package slug' => ['amazee-ai', 'amazeeai'];
        yield 'uppercase package slug' => ['Open-AI', 'openai'];
    }
}
