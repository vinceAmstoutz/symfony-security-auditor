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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

/**
 * The names people know the providers `init` lists by, in place of the
 * symfony/ai platform keys the configuration is written with.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProviderNames
{
    private const array NAMES = [
        'anthropic' => 'Anthropic (Claude)',
        'openai' => 'OpenAI (GPT)',
        'gemini' => 'Google AI Studio (Gemini)',
        'mistral' => 'Mistral AI',
        'deepseek' => 'DeepSeek',
        'cerebras' => 'Cerebras',
        'cohere' => 'Cohere',
        'fireworks' => 'Fireworks AI',
        'huggingface' => 'Hugging Face',
        'minimax' => 'MiniMax',
        'ovh' => 'OVHcloud AI Endpoints',
        'perplexity' => 'Perplexity',
        'scaleway' => 'Scaleway',
        'together' => 'Together AI',
        'venice' => 'Venice AI',
        'openrouter' => 'OpenRouter',
        'edenai' => 'Eden AI',
        'generic.gateway' => 'Another OpenAI-compatible gateway (you give its URL)',
        'bedrock.default' => 'AWS Bedrock',
        'vertexai' => 'Google Vertex AI',
        'azure.default' => 'Azure OpenAI (prints a configuration to complete by hand)',
        'claudecode' => 'Claude (through the Claude Code CLI)',
        'codex' => 'ChatGPT (through the Codex CLI)',
    ];

    private const array PLATFORM_NAMES = [
        'bedrock' => 'AWS Bedrock',
        'azure' => 'Azure OpenAI',
        'generic' => 'your OpenAI-compatible gateway',
        'ollama' => 'Ollama',
    ];

    public static function of(string $provider): string
    {
        return self::NAMES[$provider] ?? $provider;
    }

    public static function ofPlatform(string $platform): string
    {
        return self::PLATFORM_NAMES[$platform] ?? self::of($platform);
    }
}
