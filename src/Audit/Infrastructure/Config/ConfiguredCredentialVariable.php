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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;

/**
 * Which environment variable the user's configuration reads the API key from;
 * none for a configuration that is missing or unreadable.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConfiguredCredentialVariable
{
    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private StandaloneConfigFileReader $standaloneConfigFileReader = new StandaloneConfigFileReader(),
    ) {}

    /**
     * Returns why the configuration's directory cannot be used (a relative
     * `SYMFONY_SECURITY_AUDITOR_HOME`), or null when it can.
     */
    public function applicationHomeRefusal(): ?string
    {
        return $this->xdgConfigPathResolver->applicationHomeRefusal();
    }

    public function name(): ?string
    {
        return $this->placeholder()?->variableName;
    }

    /**
     * Returns the placeholder the configuration reads the key of the platform
     * `provider:` selects through, else null.
     */
    public function placeholder(): ?EnvPlaceholder
    {
        $parsed = $this->parsedConfig();
        $platform = $parsed['platform'] ?? null;
        if (!\is_array($platform)) {
            return null;
        }

        $apiKey = PlatformApiKey::valueForProvider($platform, $this->activeProvider($parsed));

        return null !== $apiKey ? EnvPlaceholder::in($apiKey) : null;
    }

    public function platformNeedsNoApiKey(): bool
    {
        $parsed = $this->parsedConfig();
        $platform = $parsed['platform'] ?? null;

        if (!\is_array($platform) || [] === $platform) {
            return false;
        }

        $block = PlatformApiKey::blockForProvider($platform, $this->activeProvider($parsed));

        return null !== $block && null === PlatformApiKey::valueIn($block);
    }

    /**
     * Returns the provider `provider:` selects, else the only platform the
     * configuration declares, else null.
     */
    public function provider(): ?ConfiguredProvider
    {
        $parsed = $this->parsedConfig();
        $platform = $parsed['platform'] ?? null;
        if (!\is_array($platform)) {
            return null;
        }

        $name = $this->activeProvider($parsed) ?? (1 === \count($platform) ? (string) array_key_first($platform) : null);
        if (null === $name) {
            return null;
        }

        return ConfiguredProvider::of($name, $parsed, PlatformApiKey::blockForProvider($platform, $name) ?? []);
    }

    /**
     * @param array<array-key, mixed> $parsed
     */
    private function activeProvider(array $parsed): ?string
    {
        $provider = $parsed['provider'] ?? null;

        return \is_string($provider) && '' !== $provider ? $provider : null;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function parsedConfig(): array
    {
        try {
            $configFile = $this->xdgConfigPathResolver->configFile();
        } catch (UnresolvableConfigPathException) {
            return [];
        }

        try {
            return $this->standaloneConfigFileReader->read($configFile);
        } catch (MalformedProjectConfigException) {
            return [];
        }
    }
}
