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

use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Yaml\Yaml;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneConfigLoader
{
    private const array PLATFORM_KEYS = ['provider', 'api_key', 'endpoint'];

    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private AuditConfiguration $auditConfiguration,
        private StandalonePlatformConfigResolver $standalonePlatformConfigResolver,
    ) {}

    public function load(): StandaloneConfig
    {
        $configFile = $this->xdgConfigPathResolver->configFile();
        $rawConfig = is_file($configFile) ? $this->parse($configFile) : [];

        $platform = $this->standalonePlatformConfigResolver->resolve($rawConfig);
        $auditConfig = (new Processor())->processConfiguration(
            $this->auditConfiguration,
            [array_diff_key($rawConfig, array_flip(self::PLATFORM_KEYS))],
        );

        return new StandaloneConfig($auditConfig, $platform);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function parse(string $configFile): array
    {
        $parsed = Yaml::parseFile($configFile);

        return \is_array($parsed) ? $parsed : [];
    }
}
