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
use Symfony\AI\Platform\Platform;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\CliAgentPlatform;

/**
 * The platforms that run a coding agent's own CLI on the user's subscription
 * instead of calling an API. `symfony/ai-bundle` declares none of them, so
 * their blocks are kept out of its configuration and wired here.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CliAgentPlatforms
{
    /**
     * @var array<string, class-string>
     */
    public const array FACTORIES = [
        'claudecode' => ClaudeCodeFactory::class,
    ];

    /**
     * @var array<string, string>
     */
    public const array DEFAULT_MODELS = [
        'claudecode' => 'opus',
    ];

    private const array TOOL_FREE_AUDIT = [
        'tools_enabled' => false,
        'structured_collection' => false,
        'reviewer_tools_enabled' => false,
        'reviewer_structured_collection' => false,
    ];

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
     * The CLI runs with its built-in tools off and takes no tool of the
     * auditor's, so a run on it reads the attacker's and the reviewer's
     * answers as JSON.
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

        $audit = $auditConfig['audit'] ?? [];

        return [...$auditConfig, 'audit' => [...(\is_array($audit) ? $audit : []), ...self::TOOL_FREE_AUDIT]];
    }

    /**
     * @param array<array-key, mixed> $platform
     */
    public static function register(ContainerBuilder $containerBuilder, array $platform): void
    {
        foreach (array_intersect_key($platform, self::FACTORIES) as $name => $settings) {
            $serviceId = \sprintf('%s%s', self::PLATFORM_SERVICE_PREFIX, $name);
            $cliServiceId = \sprintf('%s.cli', $serviceId);

            $containerBuilder->register($cliServiceId, Platform::class)
                ->setFactory([self::FACTORIES[$name], 'createPlatform'])
                ->setArguments([\is_array($settings) ? ($settings['cli_binary'] ?? null) : null, ContainerParameterSyntax::escape(sys_get_temp_dir())]);
            $containerBuilder->register($serviceId, CliAgentPlatform::class)
                ->setArguments([new Reference($cliServiceId)])
                ->addTag(self::PLATFORM_TAG, ['name' => $name]);
        }
    }
}
