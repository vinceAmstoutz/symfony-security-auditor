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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingCliAgentBridgeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatformFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentWorkingDirectory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SubscriptionClis;

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
     * The effort levels both CLIs take, Claude Code as `--effort`, Codex as
     * its `model_reasoning_effort`.
     */
    public const array EFFORT_LEVELS = ['low', 'medium', 'high', 'xhigh', 'max'];

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

    private const string REASONING_CONFIG_PLATFORM = 'codex';

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
        return null === self::activeAgentOf($standalonePlatformConfig) ? $auditConfig : self::withToolFreeAudit($auditConfig);
    }

    /**
     * The CLI the standalone `provider:` selects, if it selects one.
     */
    public static function activeAgentOf(StandalonePlatformConfig $standalonePlatformConfig): ?string
    {
        $provider = $standalonePlatformConfig->activeProvider;

        return null !== $provider && \array_key_exists($provider, self::FACTORIES) ? $provider : null;
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

    /**
     * Returns the CLI an application's `cli_agent.cli_binary` names, if any.
     *
     * @param array<array-key, mixed> $config the processed bundle configuration
     */
    public static function cliBinaryIn(array $config): ?string
    {
        $cliBinary = \is_array($config['cli_agent'] ?? null) ? ($config['cli_agent']['cli_binary'] ?? null) : null;

        return \is_string($cliBinary) ? $cliBinary : null;
    }

    public static function serviceIdOf(string $platform): string
    {
        return \sprintf('%s%s', self::PLATFORM_SERVICE_PREFIX, $platform);
    }

    /**
     * @param array<array-key, mixed>                $platform
     * @param array<key-of<self::FACTORIES>, string> $factories
     *
     * @throws MissingCliAgentBridgeException when the bridge of a configured CLI agent is not installed
     */
    public static function register(ContainerBuilder $containerBuilder, array $platform, array $factories = self::FACTORIES): void
    {
        $cliAgents = array_intersect_key($factories, $platform);

        foreach ($cliAgents as $name => $factory) {
            if (!class_exists($factory)) {
                throw MissingCliAgentBridgeException::forCliAgent($name, ComposerBridgeInstaller::packageFor($name));
            }
        }

        foreach ($cliAgents as $name => $factory) {
            $settings = $platform[$name];
            $serviceId = self::serviceIdOf($name);
            $cliServiceId = \sprintf('%s.cli', $serviceId);
            $workingDirectoryServiceId = \sprintf('%s.working_directory', $serviceId);

            $containerBuilder->register($workingDirectoryServiceId, CliAgentWorkingDirectory::class);
            $containerBuilder->register($cliServiceId, Platform::class)
                ->setFactory([CliAgentPlatformFactory::class, 'create'])
                ->setArguments([$factory, \is_array($settings) ? ($settings['cli_binary'] ?? null) : null, new Reference($workingDirectoryServiceId), SubscriptionClis::bundled()->of($name)?->billingVariables() ?? []]);
            $containerBuilder->register($serviceId, CliAgentPlatform::class)
                ->setArguments([new Reference($cliServiceId), new Reference($workingDirectoryServiceId), self::optionsOf($name, $settings), \in_array($name, self::SHARED_PROMPT_ARGUMENT, true)])
                ->addTag(self::PLATFORM_TAG);
        }
    }

    /**
     * The isolating options, plus the effort in the spelling each CLI reads.
     *
     * @param key-of<self::ISOLATING_OPTIONS> $name
     *
     * @return array<string, mixed>
     */
    private static function optionsOf(string $name, mixed $settings): array
    {
        $options = [...self::ISOLATING_OPTIONS[$name], ...SubscriptionClis::bundled()->of($name)?->subscriptionOnlyOptions() ?? []];
        $effort = \is_array($settings) ? ($settings['effort'] ?? null) : null;

        if (!\is_string($effort)) {
            return $options;
        }

        return self::REASONING_CONFIG_PLATFORM === $name
            ? [...$options, 'config' => [...self::ISOLATING_OPTIONS[self::REASONING_CONFIG_PLATFORM]['config'], \sprintf('model_reasoning_effort="%s"', $effort)]]
            : [...$options, 'effort' => $effort];
    }
}
