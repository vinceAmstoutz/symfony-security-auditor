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

    public function name(): ?string
    {
        $platform = $this->platformConfig();
        if (null === $platform) {
            return null;
        }

        $apiKey = PlatformApiKey::valueIn($platform);

        return null !== $apiKey ? EnvPlaceholder::in($apiKey)?->variableName : null;
    }

    /**
     * @return array<array-key, mixed>|null
     */
    private function platformConfig(): ?array
    {
        $platform = $this->parsedConfig()['platform'] ?? null;

        return \is_array($platform) ? $platform : null;
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
