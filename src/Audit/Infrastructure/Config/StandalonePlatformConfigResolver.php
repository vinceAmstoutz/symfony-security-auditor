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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandalonePlatformConfigResolver
{
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
        private CredentialStoreInterface $credentialStore = new NullCredentialStore(),
    ) {}

    /**
     * @param array<array-key, mixed> $rawConfig
     *
     * @throws MissingPlatformException
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
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
     * @throws UnreadableCredentialStoreException
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
     * @throws UnreadableCredentialStoreException
     */
    private function resolveValue(string $value, bool $credentialsRequired): string
    {
        $envPlaceholder = EnvPlaceholder::in($value);
        if (!$envPlaceholder instanceof EnvPlaceholder) {
            return $value;
        }

        return $envPlaceholder->readsFile
            ? $this->resolveCredentialFile($envPlaceholder->variableName, $credentialsRequired)
            : $this->resolveEnvironmentVariable($envPlaceholder->variableName, $credentialsRequired);
    }

    /**
     * An exported variable outranks the stored credential, so a container, a
     * CI job or a `VAR=$(pass show …)` prefix keeps deciding what a run
     * authenticates with on a machine that also has one stored.
     *
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialStoreException
     */
    private function resolveEnvironmentVariable(string $name, bool $credentialsRequired): string
    {
        $resolved = $this->environment[$name] ?? '';
        if ('' !== $resolved) {
            return $resolved;
        }

        $stored = $this->credentialStore->read($name);
        if (null !== $stored) {
            return $stored;
        }

        if ($credentialsRequired) {
            throw MissingEnvironmentVariableException::forName($name);
        }

        return self::UNNEEDED_CREDENTIAL;
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
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
