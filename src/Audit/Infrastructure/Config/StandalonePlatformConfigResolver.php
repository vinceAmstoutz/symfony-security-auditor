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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingEnvironmentVariableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MissingPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnreadableCredentialStoreException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnsupportedEnvPlaceholderException;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class StandalonePlatformConfigResolver
{
    /**
     * Stands in for a credential the run does not need: in a `--dry-run` or on
     * a platform `provider:` does not select. No provider accepts it as a key.
     */
    public const string UNNEEDED_CREDENTIAL = 'unneeded-for-this-run';

    /**
     * @param array<string, string>                $environment
     * @param array<string, array<string, string>> $platformEnvironments variables only the block of the platform they are keyed by reads, when the run calls that platform
     */
    public function __construct(
        private array $environment = [],
        private Filesystem $filesystem = new Filesystem(),
        private CredentialStoreInterface $credentialStore = new NullCredentialStore(),
        private array $platformEnvironments = [],
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
        $activeProvider = \is_string($activeProvider) && '' !== $activeProvider ? $activeProvider : $this->loneCliAgentIn($platform);

        $calledPlatform = $this->calledPlatformWithEnvironment($platform, $activeProvider);
        if (null === $calledPlatform) {
            return new StandalonePlatformConfig($this->resolvePlatform($platform, $activeProvider, $credentialsRequired), $activeProvider);
        }

        $calledBlock = [$calledPlatform => $platform[$calledPlatform]];
        $calledBlockResolver = new self([...$this->environment, ...$this->platformEnvironments[$calledPlatform]], $this->filesystem, $this->credentialStore);

        return new StandalonePlatformConfig(
            array_replace(
                $platform,
                $this->resolvePlatform(array_diff_key($platform, $calledBlock), $activeProvider, $credentialsRequired),
                $calledBlockResolver->resolvePlatform($calledBlock, $activeProvider, $credentialsRequired),
            ),
            $activeProvider,
        );
    }

    /**
     * @param array<array-key, mixed> $platform
     *
     * @return array<array-key, mixed>
     *
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    private function resolvePlatform(array $platform, ?string $activeProvider, bool $credentialsRequired): array
    {
        return null === $activeProvider
            ? $this->resolveEnvPlaceholders($platform, $credentialsRequired)
            : $this->resolveSelected($platform, $this->selectedPath(ProviderKey::of($activeProvider)), $credentialsRequired);
    }

    /**
     * Names the platform the run calls whose block has variables of its own,
     * read from the same `provider:` and blocks the run is resolved from.
     *
     * @param array<array-key, mixed> $platform
     */
    private function calledPlatformWithEnvironment(array $platform, ?string $activeProvider): ?string
    {
        $standalonePlatformConfig = new StandalonePlatformConfig($platform, $activeProvider);
        foreach (array_keys($this->platformEnvironments) as $platformName) {
            if ($standalonePlatformConfig->runsOn($platformName) && \array_key_exists($platformName, $platform)) {
                return $platformName;
            }
        }

        return null;
    }

    /**
     * Selects a lone CLI agent block, which `symfony/ai-bundle` cannot select
     * as it selects a lone platform it declares.
     *
     * @param array<array-key, mixed> $platform
     */
    private function loneCliAgentIn(array $platform): ?string
    {
        $name = array_key_first($platform);

        return 1 === \count($platform) && \in_array($name, array_keys(CliAgentPlatforms::FACTORIES), true) ? $name : null;
    }

    /**
     * Returns the platform key, then the instance key when the provider names
     * one.
     *
     * @return non-empty-list<string>
     */
    private function selectedPath(ProviderKey $providerKey): array
    {
        return null === $providerKey->instance ? [$providerKey->platform] : [$providerKey->platform, $providerKey->instance];
    }

    /**
     * Resolves every block `provider:` does not select as a dry run does, so
     * a key the run never sends cannot stop it. A provider naming an instance
     * its platform does not hold selects nothing.
     *
     * @param array<array-key, mixed> $config
     * @param non-empty-list<string>  $selectedPath
     *
     * @return array<array-key, mixed>
     *
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    private function resolveSelected(array $config, array $selectedPath, bool $credentialsRequired): array
    {
        $selectedKey = array_shift($selectedPath);
        $resolved = [];
        foreach ($config as $key => $value) {
            $resolved[$key] = match (true) {
                $selectedKey !== (string) $key => $this->resolveEntry($key, $value, false),
                [] === $selectedPath => $this->resolveEntry($key, $value, $credentialsRequired),
                \is_array($value) => $this->resolveSelected($value, $selectedPath, $credentialsRequired),
                default => $this->resolveEntry($key, $value, false),
            };
        }

        return $resolved;
    }

    /**
     * Only an `api_key` placeholder may be read from the credential store;
     * any other is a setting the environment must supply.
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
            $resolved[$key] = $this->resolveEntry($key, $value, $credentialsRequired);
        }

        return $resolved;
    }

    /**
     * @throws MissingEnvironmentVariableException
     * @throws UnreadableCredentialFileException
     * @throws UnreadableCredentialStoreException
     * @throws UnsupportedEnvPlaceholderException
     */
    private function resolveEntry(int|string $key, mixed $value, bool $credentialsRequired): mixed
    {
        return match (true) {
            \is_array($value) => $this->resolveEnvPlaceholders($value, $credentialsRequired),
            \is_string($value) => $this->resolveValue($value, PlatformApiKey::names($key), $credentialsRequired),
            default => $value,
        };
    }

    /**
     * Resolves only the plain and `file:` spellings and refuses any other env
     * processor, such as `trim:`, by name, in a dry run too.
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
     * An exported variable outranks the stored credential. A run that needs
     * no credential never opens the store.
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
