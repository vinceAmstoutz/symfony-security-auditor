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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

use Symfony\Component\Yaml\Yaml;

/**
 * Every bundle configuration the recorded release documented — its
 * `examples/configs` files and each `symfony_security_auditor:` block of its
 * README and docs, kept under `Input/<release>/` — loaded by an application
 * that then audits the base project.
 */
final readonly class ConfigFileScenarios
{
    private const string INPUT_DIR = __DIR__.'/Input/1.21.0';

    /**
     * @return list<Scenario>
     */
    public static function all(): array
    {
        $scenarios = [];
        $files = glob(\sprintf('%s/*.yaml', self::INPUT_DIR));
        foreach (false === $files ? [] : $files as $file) {
            $name = basename($file, '.yaml');
            if (str_starts_with($name, 'standalone-')) {
                continue;
            }

            $scenarios[] = Scenario::bundle(\sprintf('config-file/%s', $name))
                ->withProjectFiles(ProjectFixtures::base())
                ->withConfig(self::bundleConfig($file))
                ->running(Step::audit(['--format' => 'json']));
        }

        return $scenarios;
    }

    /**
     * @return array<string, mixed>
     */
    private static function bundleConfig(string $file): array
    {
        $parsed = Yaml::parseFile($file);
        $config = \is_array($parsed) ? $parsed['symfony_security_auditor'] ?? [] : [];

        return \is_array($config) ? array_filter($config, \is_string(...), \ARRAY_FILTER_USE_KEY) : [];
    }
}
