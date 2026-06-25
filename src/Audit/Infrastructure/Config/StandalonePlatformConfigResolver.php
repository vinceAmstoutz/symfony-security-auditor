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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingProviderException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandalonePlatformConfigResolver
{
    private const array CREDENTIAL_KEYS = ['api_key', 'endpoint'];

    private const string ENV_PLACEHOLDER = '/^%env\(([A-Z0-9_]+)\)%$/';

    /**
     * @param array<string, string> $environment
     */
    public function __construct(
        private array $environment = [],
    ) {}

    /**
     * @param array<array-key, mixed> $rawConfig
     */
    public function resolve(array $rawConfig): StandalonePlatformConfig
    {
        $provider = $rawConfig['provider'] ?? null;
        if (!\is_string($provider) || '' === $provider) {
            throw MissingProviderException::create();
        }

        $options = [];
        foreach (self::CREDENTIAL_KEYS as $key) {
            $value = $rawConfig[$key] ?? null;
            if (\is_string($value) && '' !== $value) {
                $options[$key] = $this->resolveValue($value);
            }
        }

        return new StandalonePlatformConfig($provider, $options);
    }

    private function resolveValue(string $value): string
    {
        if (1 !== preg_match(self::ENV_PLACEHOLDER, $value, $matches)) {
            return $value;
        }

        $resolved = $this->environment[$matches[1]] ?? '';
        if ('' === $resolved) {
            throw MissingEnvironmentVariableException::forName($matches[1]);
        }

        return $resolved;
    }
}
