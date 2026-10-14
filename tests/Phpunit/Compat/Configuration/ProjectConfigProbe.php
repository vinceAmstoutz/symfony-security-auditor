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

use Symfony\Component\Config\Definition\NodeInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Yaml\Yaml;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandaloneConfigLoader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfigResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

/**
 * Whether the standalone binary lets the `.symfony-security-auditor.yaml` of
 * the folder it runs in set one path of the configuration, over a user
 * configuration that names a platform and a model: the keys only the user may
 * set are refused there.
 */
final readonly class ProjectConfigProbe
{
    private const string USER_CONFIG = "platform:\n    generic:\n        default:\n            base_url: 'http://127.0.0.1:9'\nmodel: 'gpt-4o'\n";

    public const string ACCEPTED = 'accepted';

    public const string REFUSED = 'refused';

    /**
     * @param array<string, NodeInterface> $nodes
     */
    public static function outcome(array $nodes, string $path): string
    {
        $node = $nodes[$path];
        [$configuration] = ProbeConfiguration::holding($nodes, $path, $node->hasDefaultValue() && null !== $node->getDefaultValue() ? $node->getDefaultValue() : ProbeConfiguration::sample($node));
        unset($configuration['model']);

        $directory = \sprintf('%s/ssa-project-config-probe-%s', sys_get_temp_dir(), bin2hex(random_bytes(4)));
        $filesystem = new Filesystem();
        $filesystem->dumpFile(\sprintf('%s/config/symfony-security-auditor/config.yaml', $directory), self::USER_CONFIG);
        $filesystem->dumpFile(\sprintf('%s/project/.symfony-security-auditor.yaml', $directory), Yaml::dump($configuration, 8));

        try {
            $environment = ['HOME' => $directory, 'XDG_CONFIG_HOME' => \sprintf('%s/config', $directory), 'XDG_CACHE_HOME' => \sprintf('%s/cache', $directory), 'XDG_DATA_HOME' => \sprintf('%s/data', $directory)];
            (new StandaloneConfigLoader(XdgConfigPathResolver::fromEnvironment($environment, \PHP_OS_FAMILY), new StandalonePlatformConfigResolver($environment), \sprintf('%s/project/.symfony-security-auditor.yaml', $directory)))->load(false);
        } catch (Throwable) {
            return self::REFUSED;
        } finally {
            $filesystem->remove($directory);
        }

        return self::ACCEPTED;
    }
}
