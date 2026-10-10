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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigPlatformOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigScanOverrideException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\ProjectConfigUserOnlyKeyException;

/**
 * Reads one config file that ships with a repository — the working
 * directory's or the audited project's — and refuses what a repository may
 * not set.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GuardedProjectConfigReader
{
    public const array PLATFORM_KEYS = ['platform', 'provider'];

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
        private StandaloneConfigFileReader $standaloneConfigFileReader = new StandaloneConfigFileReader(),
        private ProjectConfigValueGuard $projectConfigValueGuard = new ProjectConfigValueGuard(),
    ) {}

    /**
     * The audited repository ships its own config file, so letting it define
     * the connection would let it point the user's resolved API credentials at
     * an endpoint of its choosing.
     *
     * @param array<array-key, mixed> $baseConfig the configuration read before this file, which it may tighten but not loosen or erase
     *
     * @return array<array-key, mixed>
     *
     * @throws MalformedProjectConfigException
     * @throws ProjectConfigPlatformOverrideException
     * @throws ProjectConfigScanOverrideException
     * @throws ProjectConfigUserOnlyKeyException
     */
    public function read(string $projectConfigFile, array $baseConfig): array
    {
        if (is_link($projectConfigFile)) {
            throw MalformedProjectConfigException::forSymlink($projectConfigFile);
        }

        $projectConfig = $this->standaloneConfigFileReader->read($projectConfigFile);
        $this->projectConfigValueGuard->assertPlainKeys($projectConfigFile, $projectConfig);
        $connectionKeys = array_values(array_intersect(self::PLATFORM_KEYS, array_keys($projectConfig)));

        if ([] !== $connectionKeys) {
            throw ProjectConfigPlatformOverrideException::forKeys($projectConfigFile, $connectionKeys);
        }

        $this->guardAgainstSectionErasure($projectConfigFile, $projectConfig, $baseConfig);
        $this->guardAgainstScanSurfaceOverride($projectConfigFile, $projectConfig);
        $this->guardAgainstUserOnlyOverride($projectConfigFile, $projectConfig);
        $this->guardAgainstLoosenedBudget($projectConfigFile, $projectConfig, $baseConfig);
        $this->projectConfigValueGuard->assertLiteralPlainText($projectConfigFile, $projectConfig);

        return $projectConfig;
    }

    /**
     * A non-map project value would overwrite a whole section of the base
     * configuration when the two are merged, so `audit: []` or `audit: ~`
     * would drop the user's budget caps and custom skills without ever naming
     * them; a repository may override single keys beneath a section, never the
     * section itself.
     *
     * @param array<array-key, mixed> $projectConfig
     * @param array<array-key, mixed> $baseConfig
     *
     * @throws ProjectConfigUserOnlyKeyException
     */
    private function guardAgainstSectionErasure(string $projectConfigFile, array $projectConfig, array $baseConfig): void
    {
        foreach ($projectConfig as $key => $value) {
            if (!$this->isMap($value) && $this->isMap($baseConfig[$key] ?? null)) {
                throw ProjectConfigUserOnlyKeyException::forErasedSection($projectConfigFile, (string) $key);
            }
        }
    }

    /**
     * @phpstan-assert-if-true array<array-key, mixed> $value
     */
    private function isMap(mixed $value): bool
    {
        return \is_array($value) && !array_is_list($value);
    }

    /**
     * A project file may cap the run tighter than the configuration before it
     * — a CI repository lowering its own spend is legitimate — but never
     * loosen it: a raised, removed or non-numeric cap decides what the run
     * spends, so it stays the user's alone. A merge writes a null or empty
     * `budget` over the caps before it, which is why those count as loosening
     * too.
     *
     * @param array<array-key, mixed> $projectConfig
     * @param array<array-key, mixed> $baseConfig
     *
     * @throws ProjectConfigUserOnlyKeyException
     */
    private function guardAgainstLoosenedBudget(string $projectConfigFile, array $projectConfig, array $baseConfig): void
    {
        $audit = $projectConfig['audit'] ?? null;
        if (!\is_array($audit) || !\array_key_exists('budget', $audit)) {
            return;
        }

        if (!\is_array($audit['budget']) || [] === $audit['budget']) {
            throw ProjectConfigUserOnlyKeyException::forLoosenedBudget($projectConfigFile, 'audit.budget');
        }

        foreach ($audit['budget'] as $cap => $value) {
            if (!$this->tightensCap($cap, $value, $this->budgetOf($baseConfig))) {
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
     * A known cap, given as a number no higher than the number before it for
     * that cap; a cap left open can only be tightened.
     *
     * @param array<array-key, mixed> $baseBudget
     */
    private function tightensCap(int|string $cap, mixed $value, array $baseBudget): bool
    {
        if (!\in_array($cap, self::BUDGET_CAPS, true) || (!\is_int($value) && !\is_float($value))) {
            return false;
        }

        $baseCap = $baseBudget[$cap] ?? null;

        return (!\is_int($baseCap) && !\is_float($baseCap)) || $value <= $baseCap;
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
