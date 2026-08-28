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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandalonePlatformConfigResolver
{
    private const string ENV_PLACEHOLDER = '/^%env\(([^)]+)\)%$/';

    /**
     * Stands in for a credential a run has been told it will not need — a
     * `--dry-run`, which estimates cost from the scanned files and never
     * reaches the provider. It is deliberately not a plausible key: were a
     * code path ever to send it, the provider rejects it outright rather than
     * charging someone.
     */
    public const string UNNEEDED_CREDENTIAL = 'unneeded-for-this-run';

    /**
     * @param array<string, string> $environment
     */
    public function __construct(
        private array $environment = [],
    ) {}

    /**
     * @param array<array-key, mixed> $rawConfig
     *
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     */
    public function resolve(array $rawConfig, bool $credentialsRequired = true): StandalonePlatformConfig
    {
        $platform = $rawConfig['platform'] ?? null;
        if (!\is_array($platform) || [] === $platform) {
            throw MissingPlatformException::create();
        }

        $activeProvider = $rawConfig['provider'] ?? null;

        return new StandalonePlatformConfig(
            $this->resolveEnvPlaceholders($platform, $credentialsRequired),
            \is_string($activeProvider) && '' !== $activeProvider ? $activeProvider : null,
        );
    }

    /**
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     *
     * @throws MissingEnvironmentVariableException
     */
    private function resolveEnvPlaceholders(array $config, bool $credentialsRequired): array
    {
        $resolved = [];
        foreach ($config as $key => $value) {
            $resolved[$key] = match (true) {
                \is_array($value) => $this->resolveEnvPlaceholders($value, $credentialsRequired),
                \is_string($value) => $this->resolveValue($value, $credentialsRequired),
                default => $value,
            };
        }

        return $resolved;
    }

    /**
     * @throws MissingEnvironmentVariableException
     */
    private function resolveValue(string $value, bool $credentialsRequired): string
    {
        if (1 !== preg_match(self::ENV_PLACEHOLDER, $value, $matches)) {
            return $value;
        }

        $resolved = $this->environment[$matches[1]] ?? '';
        if ('' !== $resolved) {
            return $resolved;
        }

        if ($credentialsRequired) {
            throw MissingEnvironmentVariableException::forName($matches[1]);
        }

        return self::UNNEEDED_CREDENTIAL;
    }
}
