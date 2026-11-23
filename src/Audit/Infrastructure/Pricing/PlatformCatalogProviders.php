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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing;

use function Symfony\Component\String\u;

/**
 * Maps each `symfony/ai` platform to the `symfony/models-dev` provider it
 * bills from. A platform absent here, such as a gateway or a local runtime,
 * has no listing of its own.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PlatformCatalogProviders
{
    /**
     * @var array<string, string>
     */
    public const array PROVIDERS = [
        'anthropic' => 'anthropic',
        'azure' => 'azure',
        'bedrock' => 'amazon-bedrock',
        'cerebras' => 'cerebras',
        'cohere' => 'cohere',
        'deepseek' => 'deepseek',
        'edenai' => 'edenai',
        'fireworks' => 'fireworks-ai',
        'gemini' => 'google',
        'huggingface' => 'huggingface',
        'minimax' => 'minimax',
        'mistral' => 'mistral',
        'openai' => 'openai',
        'openrouter' => 'openrouter',
        'ovh' => 'ovhcloud',
        'perplexity' => 'perplexity',
        'scaleway' => 'scaleway',
        'together' => 'togetherai',
        'venice' => 'venice',
        'vertexai' => 'google-vertex',
    ];

    private const string BEDROCK = 'bedrock';

    public static function providerOf(string $platform): ?string
    {
        return self::PROVIDERS[$platform] ?? null;
    }

    /**
     * @return list<string>
     */
    public static function listedIds(string $platform, string $model): array
    {
        return self::BEDROCK === $platform ? self::bedrockIds($model) : [$model];
    }

    /**
     * Returns the ids the Bedrock bridge sends a short name as, which the
     * catalog lists it under.
     *
     * @return list<string>
     */
    private static function bedrockIds(string $model): array
    {
        return [
            $model,
            \sprintf('amazon.%s-v1:0', $model),
            \sprintf('anthropic.%s-v1:0', $model),
            \sprintf('anthropic.%s', $model),
            \sprintf('meta.%s-v1:0', u($model)->replace('llama-3', 'llama3')->replace('.', '-')->toString()),
        ];
    }
}
