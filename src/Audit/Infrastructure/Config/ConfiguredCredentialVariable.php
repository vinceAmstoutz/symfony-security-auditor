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

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;

/**
 * Which environment variable the user's configuration reads the API key from,
 * so the credential commands default to the same name the audit will look up
 * instead of asking the user to repeat it. A configuration that is missing,
 * unreadable or not yet written simply has no answer.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConfiguredCredentialVariable
{
    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
    ) {}

    /**
     * Why the directory the configuration lives under cannot be used — a
     * relative `SYMFONY_SECURITY_AUDITOR_HOME` — or null when it can.
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
     * The placeholder the configuration reads the key through — the key of the
     * platform `provider:` selects when several are configured — or null for
     * a literal key, a platform needing none, or no configuration at all.
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
            $parsed = Yaml::parseFile($configFile);
        } catch (ParseException) {
            return [];
        }

        return \is_array($parsed) ? $parsed : [];
    }
}
