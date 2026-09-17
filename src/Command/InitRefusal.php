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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\BaseUrlPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfigKeyInstanceName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ContainerParameterSyntax;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\HandWrittenPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\InstanceKeyedPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PlatformServiceId;

/**
 * Why `init` will not write a configuration for what it was asked for, as the
 * sentence the user reads. The order is what keeps a refusal from sending the
 * reader into a second one: a platform `init` cannot write at all is named
 * before the shape of its provider string, and `--base-url` last of all, so a
 * provider that names a platform wrongly hears why before it hears that
 * `--base-url` does not apply to what it named.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class InitRefusal
{
    private const string PICK_A_NAME = 'Pick a plain name such as "%s.my_gateway".';

    private const string ENV_VAR_NAME_PATTERN = '/^[A-Za-z_]\w*$/';

    /**
     * Checked on the raw bytes, before `ProviderKeyNormalizer` — its `u()` call
     * throws on non-UTF-8 input, which must refuse rather than crash.
     */
    public static function forProviderText(string $provider): ?string
    {
        return match (true) {
            1 !== preg_match('//u', $provider) => 'The provider must be valid UTF-8 text.',
            '' === $provider => 'The provider must not be empty.',
            default => null,
        };
    }

    public static function forModel(string $model): ?string
    {
        return match (true) {
            1 !== preg_match('//u', $model) => 'The model must be valid UTF-8 text.',
            '' === $model => 'The model must not be empty.',
            default => null,
        };
    }

    public static function forEnvironmentVariable(string $envVar): ?string
    {
        return 1 !== preg_match(self::ENV_VAR_NAME_PATTERN, $envVar)
            ? \sprintf('"%s" is not a valid environment variable name (letters, digits, and underscores only; must not start with a digit).', $envVar)
            : null;
    }

    public static function forProvider(ProviderKey $providerKey, string $provider, ?string $baseUrl, string $configFile): ?string
    {
        if ('' === $providerKey->platform) {
            return \sprintf('"%s" names no platform before the dot. Give the platform first, for example "generic.my_gateway".', $provider);
        }

        return self::forUnwritablePlatform($providerKey, $provider, $configFile)
            ?? self::forInstanceShape($providerKey, $provider)
            ?? self::forInapplicableBaseUrl($providerKey, $provider, $baseUrl);
    }

    public static function forResolvedBaseUrl(ProviderKey $providerKey, string $provider, ?string $baseUrl): ?string
    {
        if (null === $baseUrl) {
            return BaseUrlPlatforms::accept($providerKey)
                ? \sprintf('"%s" requires a base URL, so nothing was written. Re-run with --base-url=<origin>.', $provider)
                : null;
        }

        return ContainerParameterSyntax::isAbsentFrom($baseUrl)
            ? null
            : \sprintf('The base URL for "%s" holds "%%...%%", which would be read as a container parameter rather than as part of the URL. Give the URL itself, or "%%env(VAR)%%" to read it from the environment.', $provider);
    }

    private static function forUnwritablePlatform(ProviderKey $providerKey, string $provider, string $configFile): ?string
    {
        $requirement = HandWrittenPlatforms::requirementOf($providerKey);

        return null !== $requirement
            ? \sprintf('"%s" needs %s, which "init" does not write, so nothing was created. Write the block by hand in %s; docs/configuration.md#init--generating-the-standalone-configuration says how, and what is still missing for its bridge.', $provider, $requirement, $configFile)
            : null;
    }

    private static function forInstanceShape(ProviderKey $providerKey, string $provider): ?string
    {
        if (InstanceKeyedPlatforms::needsAnInstance($providerKey)) {
            return \sprintf('"%1$s" is configured per instance, so it needs an instance name: use "%1$s.<instance>", for example "%1$s.my_gateway".', $provider);
        }

        if (InstanceKeyedPlatforms::rejectsAnInstance($providerKey)) {
            return \sprintf('"%s" takes a single connection block and names no instance, so drop the instance and use "%s".', $provider, $providerKey->platform);
        }

        return null !== $providerKey->instance
            ? self::forInstanceName($providerKey->instance, $provider, $providerKey->platform)
            : null;
    }

    private static function forInstanceName(string $instance, string $provider, string $platform): ?string
    {
        if (!ConfigKeyInstanceName::isUsable($instance)) {
            return self::sentence('"%s" uses an instance name the config file cannot be read back with: "0", ".inf", ".nan", a YAML tag or the merge key are all read back as something else.', $provider, $platform);
        }

        if (!PlatformServiceId::accepts($instance)) {
            return self::sentence('"%s" uses an instance name holding a character a service name cannot contain: an apostrophe, a line break, a null byte, or a trailing backslash.', $provider, $platform);
        }

        if (!ContainerParameterSyntax::isAbsentFrom($instance)) {
            return self::sentence('"%s" uses an instance name holding "%%...%%", which would be read as a container parameter rather than as part of the name.', $provider, $platform);
        }

        return null;
    }

    private static function forInapplicableBaseUrl(ProviderKey $providerKey, string $provider, ?string $baseUrl): ?string
    {
        return null !== $baseUrl && !BaseUrlPlatforms::accept($providerKey)
            ? \sprintf('--base-url applies to the platforms that expose one (%s); "%s" has no base_url key.', implode(', ', BaseUrlPlatforms::writableShapes()), $provider)
            : null;
    }

    private static function sentence(string $reason, string $provider, string $platform): string
    {
        return \sprintf('%s %s', \sprintf($reason, $provider), \sprintf(self::PICK_A_NAME, $platform));
    }
}
