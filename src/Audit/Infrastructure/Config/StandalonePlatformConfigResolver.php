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

use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandalonePlatformConfigResolver
{
    private const string ENV_PLACEHOLDER = '/^%env\(([^)]+)\)%$/';

    private const string FILE_PROCESSOR = 'file:';

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
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    /**
     * @param array<array-key, mixed> $rawConfig
     *
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
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
     * @throws UnreadableCredentialFileException
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
     * @throws UnreadableCredentialFileException
     */
    private function resolveValue(string $value, bool $credentialsRequired): string
    {
        if (1 !== preg_match(self::ENV_PLACEHOLDER, $value, $matches)) {
            return $value;
        }

        $expression = $matches[1];

        return str_starts_with($expression, self::FILE_PROCESSOR)
            ? $this->resolveCredentialFile(substr($expression, \strlen(self::FILE_PROCESSOR)), $credentialsRequired)
            : $this->resolveEnvironmentVariable($expression, $credentialsRequired);
    }

    /**
     * @throws MissingEnvironmentVariableException
     */
    private function resolveEnvironmentVariable(string $name, bool $credentialsRequired): string
    {
        $resolved = $this->environment[$name] ?? '';
        if ('' !== $resolved) {
            return $resolved;
        }

        if ($credentialsRequired) {
            throw MissingEnvironmentVariableException::forName($name);
        }

        return self::UNNEEDED_CREDENTIAL;
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     */
    private function resolveCredentialFile(string $name, bool $credentialsRequired): string
    {
        $path = $this->environment[$name] ?? '';
        if ('' === $path) {
            return $this->resolveEnvironmentVariable($name, $credentialsRequired);
        }

        try {
            $credential = trim($this->filesystem->readFile($path));
        } catch (IOException) {
            if ($credentialsRequired) {
                throw UnreadableCredentialFileException::forPath($path);
            }

            return self::UNNEEDED_CREDENTIAL;
        }

        if ('' !== $credential) {
            return $credential;
        }

        if ($credentialsRequired) {
            throw UnreadableCredentialFileException::forBlankFile($path);
        }

        return self::UNNEEDED_CREDENTIAL;
    }
}
