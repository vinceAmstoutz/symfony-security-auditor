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

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;

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

    /**
     * @throws UnresolvableConfigPathException
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws MalformedProjectConfigException
     */
    public function load(): StandaloneConfig
    {
        $rawConfig = $this->merge(
            $this->read($this->xdgConfigPathResolver->configFile()),
            $this->read($this->projectConfigFile),
        );

        $standalonePlatformConfig = $this->standalonePlatformConfigResolver->resolve($rawConfig);
        $auditConfig = array_diff_key($rawConfig, array_flip(self::PLATFORM_KEYS));

        return new StandaloneConfig($auditConfig, $standalonePlatformConfig);
    }

    /**
     * Unlike `array_replace_recursive`, list values are replaced wholesale: a
     * project config declaring `included_paths: [app]` fully overrides a user
     * config's `[src, config, templates]` instead of index-merging into
     * `[app, config, templates]`.
     *
     * @param array<array-key, mixed> $base
     * @param array<array-key, mixed> $override
     *
     * @return array<array-key, mixed>
     */
    private function merge(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            $baseValue = $base[$key] ?? null;
            $base[$key] = $this->isMap($value) && $this->isMap($baseValue)
                ? $this->merge($baseValue, $value)
                : $value;
        }

        return $base;
    }

    /**
     * @phpstan-assert-if-true array<array-key, mixed> $value
     */
    private function isMap(mixed $value): bool
    {
        return \is_array($value) && !array_is_list($value);
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws MalformedProjectConfigException
     */
    private function read(?string $configFile): array
    {
        if (null === $configFile || !is_file($configFile)) {
            return [];
        }

        try {
            $parsed = Yaml::parseFile($configFile);
        } catch (ParseException $parseException) {
            throw MalformedProjectConfigException::fromParseException($configFile, $parseException);
        }

        return \is_array($parsed) ? $parsed : [];
    }
}
