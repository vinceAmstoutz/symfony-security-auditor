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
    private const array PLATFORM_KEYS = ['platform', 'provider'];

    private const array SCAN_SURFACE_KEYS = ['import_sarif'];

    /**
     * What a run spends, trusts and writes is the user's to decide: the
     * audited repository may tune what is audited and how, not lift the
     * budget cap, switch secret scrubbing or the offline guard off, put words
     * in the attacker's system prompt or in the risk markers it is handed,
     * widen the files the model's tools may open, or aim the cache at files it
     * ships.
     */
    private const array USER_ONLY_PATHS = ['cache', 'privacy', 'audit.custom_skills', 'audit.output', 'audit.tools_scope', 'scan.secret_scrubbing', 'scan.custom_risk_patterns'];

    private const array BUDGET_CAPS = ['max_tokens', 'max_cost_usd'];

    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandalonePlatformConfigResolver $standalonePlatformConfigResolver,
        private ?string $projectConfigFile = null,
        private ProjectConfigValueGuard $projectConfigValueGuard = new ProjectConfigValueGuard(),
        private StandaloneConfigFileReader $standaloneConfigFileReader = new StandaloneConfigFileReader(),
    ) {}

    public function withProjectConfigFile(?string $projectConfigFile): self
    {
        return new self(
            $this->xdgConfigPathResolver,
            $this->standalonePlatformConfigResolver,
            $projectConfigFile,
            $this->projectConfigValueGuard,
            $this->standaloneConfigFileReader,
        );
    }

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
    public function load(bool $credentialsRequired = true): StandaloneConfig
    {
        $userConfigFile = $this->xdgConfigPathResolver->configFile();
        $userConfig = $this->standaloneConfigFileReader->read($userConfigFile);
        $userTimeout = HttpTimeout::in($userConfig, $userConfigFile);
        $projectConfig = $this->readProjectConfig($userConfig);
        $rawConfig = $this->merge($userConfig, $projectConfig);

        $standalonePlatformConfig = $this->standalonePlatformConfigResolver->resolve($rawConfig, $credentialsRequired);
        $auditConfig = array_diff_key($rawConfig, array_flip([...self::PLATFORM_KEYS, HttpTimeout::KEY]));

        return new StandaloneConfig(
            $auditConfig,
            $standalonePlatformConfig,
            $this->existingProjectConfigFile(),
            $this->projectTimeout($projectConfig, $userTimeout) ?? $userTimeout,
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
     * The audited repository ships its own config file, so letting it define
     * the connection would let it point the user's resolved API credentials at
     * an endpoint of its choosing.
     *
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
        if (null === $this->projectConfigFile) {
            return [];
        }

        if (is_link($this->projectConfigFile)) {
            throw MalformedProjectConfigException::forSymlink($this->projectConfigFile);
        }

        $projectConfig = $this->standaloneConfigFileReader->read($this->projectConfigFile);
        $this->projectConfigValueGuard->assertPlainKeys($this->projectConfigFile, $projectConfig);
        $connectionKeys = array_values(array_intersect(self::PLATFORM_KEYS, array_keys($projectConfig)));

        if ([] !== $connectionKeys) {
            throw ProjectConfigPlatformOverrideException::forKeys($this->projectConfigFile, $connectionKeys);
        }

        $this->guardAgainstSectionErasure($this->projectConfigFile, $projectConfig, $userConfig);
        $this->guardAgainstScanSurfaceOverride($this->projectConfigFile, $projectConfig);
        $this->guardAgainstUserOnlyOverride($this->projectConfigFile, $projectConfig);
        $this->guardAgainstLoosenedBudget($this->projectConfigFile, $projectConfig, $userConfig);
        $this->projectConfigValueGuard->assertLiteralPlainText($this->projectConfigFile, $projectConfig);

        return ProjectConfigPathAnchor::anchored($projectConfig, $this->projectConfigFile);
    }

    /**
     * `merge()` writes a non-map project value over a whole user section, so
     * `audit: []` or `audit: ~` would drop the user's budget caps and custom
     * skills without ever naming them; a repository may override single keys
     * beneath a section, never the section itself.
     *
     * @param array<array-key, mixed> $projectConfig
     * @param array<array-key, mixed> $userConfig
     *
     * @throws ProjectConfigUserOnlyKeyException
     */
    private function guardAgainstSectionErasure(string $projectConfigFile, array $projectConfig, array $userConfig): void
    {
        foreach ($projectConfig as $key => $value) {
            if (!$this->isMap($value) && $this->isMap($userConfig[$key] ?? null)) {
                throw ProjectConfigUserOnlyKeyException::forErasedSection($projectConfigFile, (string) $key);
            }
        }
    }

    /**
     * A project file may cap the run tighter than the user config — a CI
     * repository lowering its own spend is legitimate — but never loosen it:
     * a raised, removed or non-numeric cap decides what the run spends, so it
     * stays the user's alone. `merge()` writes a null or empty `budget` over
     * the user's caps, which is why those count as loosening too.
     *
     * @param array<array-key, mixed> $projectConfig
     * @param array<array-key, mixed> $userConfig
     *
     * @throws ProjectConfigUserOnlyKeyException
     */
    private function guardAgainstLoosenedBudget(string $projectConfigFile, array $projectConfig, array $userConfig): void
    {
        $audit = $projectConfig['audit'] ?? null;
        if (!\is_array($audit) || !\array_key_exists('budget', $audit)) {
            return;
        }

        if (!\is_array($audit['budget']) || [] === $audit['budget']) {
            throw ProjectConfigUserOnlyKeyException::forLoosenedBudget($projectConfigFile, 'audit.budget');
        }

        foreach ($audit['budget'] as $cap => $value) {
            if (!$this->tightensCap($cap, $value, $this->budgetOf($userConfig))) {
                throw ProjectConfigUserOnlyKeyException::forLoosenedBudget($projectConfigFile, \sprintf('audit.budget.%s', $cap));
            }
        }
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     */
    private function budgetOf(array $config): array
    {
        $audit = $config['audit'] ?? null;
        $budget = \is_array($audit) ? ($audit['budget'] ?? null) : null;

        return \is_array($budget) ? $budget : [];
    }

    /**
     * A known cap, given as a number no higher than the user's own number for
     * it; a cap the user left open can only be tightened.
     *
     * @param array<array-key, mixed> $userBudget
     */
    private function tightensCap(int|string $cap, mixed $value, array $userBudget): bool
    {
        if (!\in_array($cap, self::BUDGET_CAPS, true) || (!\is_int($value) && !\is_float($value))) {
            return false;
        }

        $userCap = $userBudget[$cap] ?? null;

        return (!\is_int($userCap) && !\is_float($userCap)) || $value <= $userCap;
    }

    /**
     * @param array<array-key, mixed> $projectConfig
     *
     * @throws ProjectConfigUserOnlyKeyException
     */
    private function guardAgainstUserOnlyOverride(string $projectConfigFile, array $projectConfig): void
    {
        $declared = array_values(array_filter(
            self::USER_ONLY_PATHS,
            fn (string $path): bool => $this->declares($projectConfig, explode('.', $path)),
        ));

        if ([] !== $declared) {
            throw ProjectConfigUserOnlyKeyException::forKeys($projectConfigFile, $declared);
        }
    }

    /**
     * @param array<array-key, mixed> $config
     * @param non-empty-list<string>  $segments
     */
    private function declares(array $config, array $segments): bool
    {
        $key = array_shift($segments);
        if (!\array_key_exists($key, $config)) {
            return false;
        }

        if ([] === $segments) {
            return true;
        }

        return \is_array($config[$key]) && $this->declares($config[$key], $segments);
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
}
