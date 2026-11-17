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
 * @internal not part of the BC promise — see docs/versioning.md
 */
enum ModelAccess: string
{
    case ApiKey = 'api-key';
    case Cloud = 'cloud';
    case Gateway = 'gateway';
    case Local = 'local';
    case Subscription = 'subscription';

    private const array CLOUD_PLATFORMS = ['bedrock.default', 'vertexai', 'azure.default'];

    private const array GATEWAYS = ['openrouter', 'edenai', 'generic.gateway'];

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
            self::ApiKey => array_values(array_diff(InitProviderChoices::names(), self::CLOUD_PLATFORMS, self::GATEWAYS, array_keys(CliAgentPlatforms::FACTORIES))),
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::ApiKey => 'An API key from an AI provider (Anthropic, OpenAI, Mistral, Gemini, …)',
            self::Cloud => 'A cloud account (AWS Bedrock, Google Vertex AI, Azure)',
            self::Gateway => 'An AI gateway or router (OpenRouter, Eden AI, any OpenAI-compatible endpoint)',
            self::Local => 'A model running on this machine (Ollama)',
            self::Subscription => 'A Claude or ChatGPT subscription (through the Claude Code or Codex CLI)',
        };
    }
}
