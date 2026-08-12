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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigPlatformOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigScanOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneConfigLoader
{
    private const array PLATFORM_KEYS = ['platform', 'provider'];

    private const array SCAN_SURFACE_KEYS = ['import_sarif'];

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
     * @throws ProjectConfigPlatformOverrideException
     * @throws ProjectConfigScanOverrideException
     */
    public function load(): StandaloneConfig
    {
        $rawConfig = $this->merge(
            $this->read($this->xdgConfigPathResolver->configFile()),
            $this->readProjectConfig(),
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
     * The audited repository ships its own config file, so letting it define
     * the connection would let it point the user's resolved API credentials at
     * an endpoint of its choosing.
     *
     * @return array<array-key, mixed>
     *
     * @throws MalformedProjectConfigException
     * @throws ProjectConfigPlatformOverrideException
     * @throws ProjectConfigScanOverrideException
     */
    private function readProjectConfig(): array
    {
        if (null === $this->projectConfigFile) {
            return [];
        }

        $projectConfig = $this->read($this->projectConfigFile);
        $connectionKeys = array_values(array_intersect(self::PLATFORM_KEYS, array_keys($projectConfig)));

        if ([] !== $connectionKeys) {
            throw ProjectConfigPlatformOverrideException::forKeys($this->projectConfigFile, $connectionKeys);
        }

        $this->guardAgainstScanSurfaceOverride($this->projectConfigFile, $projectConfig);

        return $projectConfig;
    }

    /**
     * `scan.import_sarif` reads whatever file it names — an absolute path or
     * one escaping the project root included — and folds its contents into
     * the LLM prompt. Letting the audited repository declare it would let the
     * repository point the scanner at paths of its own choosing, the same
     * threat model already applied to `platform`/`provider`.
     *
     * @param array<array-key, mixed> $projectConfig
     *
     * @throws ProjectConfigScanOverrideException
     */
    private function guardAgainstScanSurfaceOverride(string $projectConfigFile, array $projectConfig): void
    {
        $scanConfig = $projectConfig['scan'] ?? null;
        if (!\is_array($scanConfig)) {
            return;
        }

        $scanKeys = array_values(array_intersect(self::SCAN_SURFACE_KEYS, array_keys($scanConfig)));
        if ([] === $scanKeys) {
            return;
        }

        throw ProjectConfigScanOverrideException::forKeys($projectConfigFile, array_map(static fn (string $key): string => \sprintf('scan.%s', $key), $scanKeys));
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws MalformedProjectConfigException
     */
    private function read(string $configFile): array
    {
        if (!is_file($configFile)) {
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
