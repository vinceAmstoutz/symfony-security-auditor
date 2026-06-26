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

use Symfony\Component\Yaml\Yaml;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneConfigLoader
{
    private const array PLATFORM_KEYS = ['platform', 'provider'];

    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandalonePlatformConfigResolver $standalonePlatformConfigResolver,
        private ?string $projectConfigFile = null,
    ) {}

    public function load(): StandaloneConfig
    {
        $rawConfig = array_replace_recursive(
            $this->read($this->xdgConfigPathResolver->configFile()),
            $this->read($this->projectConfigFile),
        );

        $standalonePlatformConfig = $this->standalonePlatformConfigResolver->resolve($rawConfig);
        $auditConfig = array_diff_key($rawConfig, array_flip(self::PLATFORM_KEYS));

        return new StandaloneConfig($auditConfig, $standalonePlatformConfig);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function read(?string $configFile): array
    {
        if (null === $configFile || !is_file($configFile)) {
            return [];
        }

        $parsed = Yaml::parseFile($configFile);

        return \is_array($parsed) ? $parsed : [];
    }
}
