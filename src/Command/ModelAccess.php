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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CliAgentPlatforms;

/**
 * How someone running `init` reaches an AI model, which narrows the
 * providers it then lists.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
enum ModelAccess: string
{
    case Subscription = 'subscription';
    case ApiKey = 'api-key';
    case Local = 'local';
    case Gateway = 'gateway';
    case Cloud = 'cloud';

    private const array CLOUD_PLATFORMS = ['bedrock.default', 'vertexai', 'azure.default'];

    private const array GATEWAYS = ['openrouter', 'edenai', 'generic.gateway'];

    private const array MOST_COMMON_API_KEYS = ['anthropic', 'openai', 'gemini', 'mistral', 'deepseek'];

    /**
     * @return list<string>
     */
    public function providers(): array
    {
        return match ($this) {
            self::Cloud => self::CLOUD_PLATFORMS,
            self::Gateway => self::GATEWAYS,
            self::Subscription => array_keys(CliAgentPlatforms::FACTORIES),
            self::Local => ['ollama'],
            self::ApiKey => self::mostCommonFirst(array_diff(InitProviderChoices::names(), self::CLOUD_PLATFORMS, self::GATEWAYS, array_keys(CliAgentPlatforms::FACTORIES))),
        };
    }

    public function providerQuestion(): string
    {
        return match ($this) {
            self::Subscription => 'Which subscription do you have?',
            self::ApiKey => 'Which company is your API key from? Pick a number, or type a provider name',
            self::Cloud => 'Which cloud do you use?',
            default => 'Which gateway do you use?',
        };
    }

    /**
     * @param array<int, string> $providers
     *
     * @return list<string>
     */
    private static function mostCommonFirst(array $providers): array
    {
        return [...self::MOST_COMMON_API_KEYS, ...array_diff($providers, self::MOST_COMMON_API_KEYS)];
    }

    public function label(): string
    {
        return match ($this) {
            self::Subscription => 'A Claude or ChatGPT subscription',
            self::ApiKey => 'An API key (Anthropic, OpenAI, Mistral, …)',
            self::Local => 'A local model (Ollama)',
            self::Gateway => 'An AI gateway (OpenRouter, Eden AI, …)',
            self::Cloud => 'A cloud account (AWS, Google Cloud, Azure)',
        };
    }
}
