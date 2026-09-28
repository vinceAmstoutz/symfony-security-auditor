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
 * The `symfony/models-dev` provider listing each `symfony/ai` platform bills
 * from, so a model is priced at the rate of the platform that actually serves
 * it rather than at whichever provider re-lists the same id first. Platforms
 * absent here (a self-hosted gateway, a local runtime, a wrapper around
 * another platform) have no listing of their own to prefer.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
     * The Bedrock bridge sends a short name as `amazon.<name>-v1:0` (Nova),
     * `anthropic.<name>[-v1:0]` (Claude) or `meta.<name>-v1:0` with
     * `llama-3` folded to `llama3` and dots turned to dashes (Llama), the
     * keys the catalog lists it under.
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
