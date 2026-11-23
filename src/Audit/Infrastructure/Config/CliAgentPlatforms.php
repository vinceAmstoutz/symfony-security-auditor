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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use Symfony\AI\Platform\Bridge\ClaudeCode\Factory as ClaudeCodeFactory;
use Symfony\AI\Platform\Bridge\Codex\Factory as CodexFactory;
use Symfony\AI\Platform\Platform;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatformFactory;

/**
 * The platforms that run a coding agent's CLI on the user's subscription
 * instead of calling an API, wired here since `symfony/ai-bundle` declares
 * none of them.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class CliAgentPlatforms
{
    /**
     * @var array<string, class-string>
     */
    public const array FACTORIES = [
        'claudecode' => ClaudeCodeFactory::class,
        'codex' => CodexFactory::class,
    ];

    /**
     * @var array<string, string>
     */
    public const array DEFAULT_MODELS = [
        'claudecode' => 'opus',
        'codex' => 'gpt-5.4',
    ];

    /**
     * Turns each CLI's built-in tools off and makes it ignore the machine's
     * own configuration.
     */
    private const array ISOLATING_OPTIONS = [
        'claudecode' => ['tools' => [], 'strict_mcp_config' => true],
        'codex' => [
            'sandbox' => 'read-only',
            'skip_git_repo_check' => true,
            'ephemeral' => true,
            'ignore_user_config' => true,
            'ignore_rules' => true,
            'config' => ['features.shell_tool=false', 'web_search="disabled"'],
        ],
    ];

    private const array TOOL_FREE_AUDIT = [
        'tools_enabled' => false,
        'structured_collection' => false,
        'reviewer_tools_enabled' => false,
        'reviewer_structured_collection' => false,
    ];

    /**
     * The CLIs that join the system and user prompts into one command-line
     * argument.
     */
    private const array SHARED_PROMPT_ARGUMENT = ['codex'];

    private const string PLATFORM_SERVICE_PREFIX = 'ai.platform.';

    private const string PLATFORM_TAG = 'ai.platform';

    public static function declares(ProviderKey $providerKey): bool
    {
        return null === $providerKey->instance && \array_key_exists($providerKey->platform, self::FACTORIES);
    }

    /**
     * @param array<array-key, mixed> $platform
     *
     * @return array<array-key, mixed>
     */
    public static function withoutCliAgents(array $platform): array
    {
        return array_diff_key($platform, self::FACTORIES);
    }

    /**
     * On a CLI agent provider, reads the attacker's and the reviewer's answers
     * as JSON: the CLI takes no tool.
     *
     * @param array<array-key, mixed> $auditConfig
     *
     * @return array<array-key, mixed>
     */
    public static function auditConfigFor(array $auditConfig, StandalonePlatformConfig $standalonePlatformConfig): array
    {
        if (null === $standalonePlatformConfig->activeProvider || !\array_key_exists($standalonePlatformConfig->activeProvider, self::FACTORIES)) {
            return $auditConfig;
        }

        return self::withToolFreeAudit($auditConfig);
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    public static function withToolFreeAudit(array $config): array
    {
        $audit = $config['audit'] ?? [];

        return [...$config, 'audit' => [...(\is_array($audit) ? $audit : []), ...self::TOOL_FREE_AUDIT]];
    }

    /**
     * Returns the CLI an application's `cli_agent.platform` names, if any.
     *
     * @param array<array-key, mixed> $config the processed bundle configuration
     */
    public static function agentIn(array $config): ?string
    {
        $platform = \is_array($config['cli_agent'] ?? null) ? ($config['cli_agent']['platform'] ?? null) : null;

        return \is_string($platform) ? $platform : null;
    }

    public static function serviceIdOf(string $platform): string
    {
        return \sprintf('%s%s', self::PLATFORM_SERVICE_PREFIX, $platform);
    }

    /**
     * @param array<array-key, mixed> $platform
     */
    public static function register(ContainerBuilder $containerBuilder, array $platform): void
    {
        foreach (array_intersect_key($platform, self::FACTORIES) as $name => $settings) {
            $serviceId = self::serviceIdOf($name);
            $cliServiceId = \sprintf('%s.cli', $serviceId);

            $containerBuilder->register($cliServiceId, Platform::class)
                ->setFactory([CliAgentPlatformFactory::class, 'create'])
                ->setArguments([self::FACTORIES[$name], \is_array($settings) ? ($settings['cli_binary'] ?? null) : null]);
            $containerBuilder->register($serviceId, CliAgentPlatform::class)
                ->setArguments([new Reference($cliServiceId), self::ISOLATING_OPTIONS[$name], \in_array($name, self::SHARED_PROMPT_ARGUMENT, true)])
                ->addTag(self::PLATFORM_TAG);
        }
    }
}
