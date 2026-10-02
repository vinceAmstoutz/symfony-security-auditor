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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsupportedEnvPlaceholderException;

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
     * @throws UnsupportedEnvPlaceholderException
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
     * Only a platform's `api_key` is a credential: it alone may come out of
     * the store, and it alone is spoken of as the API key when it is missing.
     * Every other placeholder — a `base_url`, an `endpoint` — is a plain
     * setting the environment has to supply.
     *
     * @param array<array-key, mixed> $config
     *
     * @return array<array-key, mixed>
     *
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    private function resolveEnvPlaceholders(array $config, bool $credentialsRequired): array
    {
        $resolved = [];
        foreach ($config as $key => $value) {
            $resolved[$key] = match (true) {
                \is_array($value) => $this->resolveEnvPlaceholders($value, $credentialsRequired),
                \is_string($value) => $this->resolveValue($value, PlatformApiKey::names($key), $credentialsRequired),
                default => $value,
            };
        }

        return $resolved;
    }

    /**
     * Only the plain and `file:` spellings are resolved here, so a Symfony env
     * processor (`trim:`, `default::`) is refused by name rather than looked
     * up as a variable called `trim:API_KEY` that no shell can export. A dry
     * run refuses it too: no run could ever resolve it, so tolerating it would
     * pass a dry run the real one then fails.
     *
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    private function resolveValue(string $value, bool $isCredential, bool $credentialsRequired): string
    {
        $envPlaceholder = EnvPlaceholder::in($value);
        if (!$envPlaceholder instanceof EnvPlaceholder) {
            return $value;
        }

        if (!EnvironmentVariableName::isValid($envPlaceholder->variableName)) {
            throw UnsupportedEnvPlaceholderException::forPlaceholder($envPlaceholder);
        }

        $resolved = $envPlaceholder->readsFile
            ? $this->resolveCredentialFile($envPlaceholder->variableName, $isCredential, $credentialsRequired)
            : $this->resolveEnvironmentVariable($envPlaceholder->variableName, $isCredential, $credentialsRequired);

        return ContainerParameterSyntax::escape($resolved);
    }

    /**
     * An exported variable outranks the stored credential, so a container, a
     * CI job or a `VAR=$(pass show …)` prefix keeps deciding what a run
     * authenticates with on a machine that also has one stored. A run that
     * needs no credential does not open the store at all, so a store it could
     * not read cannot stop it.
     *
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialStoreException
     */
    private function resolveEnvironmentVariable(string $name, bool $isCredential, bool $credentialsRequired): string
    {
        $resolved = $this->environment[$name] ?? '';
        if ('' !== $resolved) {
            return $resolved;
        }

        $stored = $isCredential && $credentialsRequired ? $this->credentialStore->read($name) : null;
        if (null !== $stored) {
            return $stored;
        }

        if ($credentialsRequired) {
            throw $isCredential ? MissingEnvironmentVariableException::forName($name) : MissingEnvironmentVariableException::forSetting($name);
        }

        return self::UNNEEDED_CREDENTIAL;
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     */
    private function resolveCredentialFile(string $name, bool $isCredential, bool $credentialsRequired): string
    {
        $path = $this->environment[$name] ?? '';
        if ('' === $path) {
            return $this->resolveEnvironmentVariable($name, $isCredential, $credentialsRequired);
        }

        try {
            $credential = trim($this->filesystem->readFile($path));
        } catch (IOException) {
            if ($credentialsRequired) {
                throw UnreadableCredentialFileException::forVariable($name, $path);
            }

            return self::UNNEEDED_CREDENTIAL;
        }

        if ('' !== $credential) {
            return $credential;
        }

        if ($credentialsRequired) {
            throw UnreadableCredentialFileException::forBlankFile($name, $path);
        }

        return self::UNNEEDED_CREDENTIAL;
    }
}
