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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Configuration;

use Symfony\Component\Config\Definition\ArrayNode;
use Symfony\Component\Config\Definition\NodeInterface;

/**
 * Everything the configuration contract holds for one path of whichever
 * checkout is autoloaded — the snapshot `tools/Compat/record-configuration.php`
 * records from a release and `ConfigurationCompatibilityTest` compares with.
 */
final readonly class ConfigurationSnapshot
{
    public const string DEFAULT_CONFIGURATION = 'default';

    public const string PROFILE_CONFIGURATION = 'profile: ';

    private const string PROFILE = 'profile';

    /**
     * @param array<string, NodeInterface> $nodes
     *
     * @return array<string, mixed>
     */
    public static function ofPath(array $nodes, string $path): array
    {
        $node = $nodes[$path];
        $isLeaf = !$node instanceof ArrayNode;

        return [
            'node' => ConfigurationTree::describe($node),
            'values' => $isLeaf ? ConfigurationProbe::values($nodes, $path) : null,
            'environment_placeholder' => $isLeaf ? ConfigurationProbe::takesEnvironmentPlaceholder($nodes, $path) : null,
            'project_config' => str_contains($path, ConfigurationTree::ENTRY) ? null : ProjectConfigProbe::outcome($nodes, $path),
        ];
    }

    /**
     * @return array{paths: array<string, array<string, mixed>>, parameters: array<string, array<string, mixed>>}
     */
    public static function all(): array
    {
        $nodes = ConfigurationTree::nodes();
        $paths = [];
        foreach (array_keys($nodes) as $path) {
            $paths[$path] = self::ofPath($nodes, $path);
        }

        ksort($paths);

        return ['paths' => $paths, 'parameters' => self::parameters($nodes)];
    }

    /**
     * @param array<string, NodeInterface> $nodes
     *
     * @return array<string, array<string, mixed>> the published parameters of the default configuration, then of each profile
     */
    public static function parameters(array $nodes): array
    {
        $parameters = [self::DEFAULT_CONFIGURATION => ConfigurationProbe::parameters()];
        foreach (self::profiles($nodes) as $profile) {
            $parameters[\sprintf('%s%s', self::PROFILE_CONFIGURATION, $profile)] = ConfigurationProbe::parameters($profile);
        }

        return $parameters;
    }

    /**
     * @param array<string, NodeInterface> $nodes
     *
     * @return list<string>
     */
    private static function profiles(array $nodes): array
    {
        $profile = $nodes[self::PROFILE] ?? null;
        $choices = null === $profile ? null : ConfigurationTree::describe($profile)['values'];

        return \is_array($choices) ? array_values(array_filter($choices, \is_string(...))) : [];
    }
}
