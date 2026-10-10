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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigPlatformOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigScanOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigUserOnlyKeyException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsupportedEnvPlaceholderException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneConfigLoader
{
    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandalonePlatformConfigResolver $standalonePlatformConfigResolver,
        private ?string $projectConfigFile = null,
        private ProjectConfigValueGuard $projectConfigValueGuard = new ProjectConfigValueGuard(),
        private StandaloneConfigFileReader $standaloneConfigFileReader = new StandaloneConfigFileReader(),
    ) {}

    /**
     * @throws UnresolvableConfigPathException
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws MalformedProjectConfigException
     * @throws ProjectConfigPlatformOverrideException
     * @throws ProjectConfigScanOverrideException
     * @throws ProjectConfigUserOnlyKeyException
     * @throws UnsupportedEnvPlaceholderException
     */
    public function load(bool $credentialsRequired = true, ?string $auditedProjectConfigFile = null): StandaloneConfig
    {
        $userConfigFile = $this->xdgConfigPathResolver->configFile();
        $userConfig = $this->standaloneConfigFileReader->read($userConfigFile);
        $userTimeout = HttpTimeout::in($userConfig, $userConfigFile);
        $projectConfig = $this->readProjectConfig($userConfig);
        $workingDirectoryConfig = $this->merge($userConfig, $projectConfig);

        $standalonePlatformConfig = $this->standalonePlatformConfigResolver->resolve($workingDirectoryConfig, $credentialsRequired);
        $workingDirectoryTimeout = $this->projectTimeout($projectConfig, $userTimeout) ?? $userTimeout;
        $auditedProjectConfig = $this->auditedProjectConfig($auditedProjectConfigFile, $workingDirectoryConfig, $userTimeout);
        $rawConfig = $this->merge($workingDirectoryConfig, $auditedProjectConfig->config ?? []);
        $auditConfig = array_diff_key($rawConfig, array_flip([...GuardedProjectConfigReader::PLATFORM_KEYS, HttpTimeout::KEY]));

        return new StandaloneConfig(
            $auditConfig,
            $standalonePlatformConfig,
            $this->existingProjectConfigFile(),
            max($workingDirectoryTimeout, $auditedProjectConfig->httpTimeout ?? $workingDirectoryTimeout),
            $auditedProjectConfig,
        );
    }

    /**
     * The `provider:` the user config selects, read without resolving
     * anything, for a message that has to name it whether or not the
     * configuration loads. Only the user config may select one.
     */
    public function configuredProvider(): ?string
    {
        try {
            $provider = $this->standaloneConfigFileReader->read($this->xdgConfigPathResolver->configFile())['provider'] ?? null;
        } catch (UnresolvableConfigPathException|MalformedProjectConfigException) {
            return null;
        }

        return \is_string($provider) && '' !== $provider ? $provider : null;
    }

    /**
     * @param array<array-key, mixed> $projectConfig
     *
     * @throws ProjectConfigUserOnlyKeyException
     */
    private function projectTimeout(array $projectConfig, float $userTimeout): ?float
    {
        return null !== $this->projectConfigFile ? HttpTimeout::raisedBy($projectConfig, $userTimeout, $this->projectConfigFile) : null;
    }

    private function existingProjectConfigFile(): ?string
    {
        return null !== $this->projectConfigFile && is_file($this->projectConfigFile) ? $this->projectConfigFile : null;
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
     * @param array<array-key, mixed> $userConfig
     *
     * @return array<array-key, mixed>
     *
     * @throws MalformedProjectConfigException
     * @throws ProjectConfigPlatformOverrideException
     * @throws ProjectConfigScanOverrideException
     * @throws ProjectConfigUserOnlyKeyException
     */
    private function readProjectConfig(array $userConfig): array
    {
        return null === $this->projectConfigFile ? [] : $this->projectConfigReader()->read($this->projectConfigFile, $userConfig);
    }

    /**
     * The audited project's own file is layered over the other two, but the
     * run never asked for it: a file this loader would refuse, or cannot read,
     * is skipped as a whole and says why, instead of stopping a run that does
     * not need it. The file of the working directory, read first, is the
     * user's own and stays strict.
     *
     * @param array<array-key, mixed> $workingDirectoryConfig
     */
    private function auditedProjectConfig(?string $auditedProjectConfigFile, array $workingDirectoryConfig, float $userTimeout): ?AuditedProjectConfig
    {
        if (!$this->isAnotherProjectConfig($auditedProjectConfigFile)) {
            return null;
        }

        try {
            $config = $this->projectConfigReader()->read($auditedProjectConfigFile, $workingDirectoryConfig);
            $httpTimeout = HttpTimeout::raisedBy($config, $userTimeout, $auditedProjectConfigFile);
        } catch (MalformedProjectConfigException|ProjectConfigPlatformOverrideException|ProjectConfigScanOverrideException|ProjectConfigUserOnlyKeyException $projectConfigRefusal) {
            return AuditedProjectConfig::skipped($auditedProjectConfigFile, $projectConfigRefusal->getMessage());
        }

        return AuditedProjectConfig::layered($auditedProjectConfigFile, ProjectConfigPathAnchor::anchored($config, $auditedProjectConfigFile), $httpTimeout);
    }

    /**
     * @phpstan-assert-if-true string $auditedProjectConfigFile
     */
    private function isAnotherProjectConfig(?string $auditedProjectConfigFile): bool
    {
        if (null === $auditedProjectConfigFile || (!is_file($auditedProjectConfigFile) && !is_link($auditedProjectConfigFile))) {
            return false;
        }

        return null === $this->projectConfigFile || realpath(\dirname($this->projectConfigFile)) !== realpath(\dirname($auditedProjectConfigFile));
    }

    private function projectConfigReader(): GuardedProjectConfigReader
    {
        return new GuardedProjectConfigReader($this->standaloneConfigFileReader, $this->projectConfigValueGuard);
    }
}
