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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;

/**
 * Every symfony/ai platform that authenticates spells its credential
 * `api_key`, whichever provider it is, so one lookup serves them all.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformApiKey
{
    private const string KEY = 'api_key';

    public static function names(int|string $key): bool
    {
        return self::KEY === $key;
    }

    /**
     * @param array<array-key, mixed> $platform
     */
    public static function valueIn(array $platform): ?string
    {
        foreach ($platform as $key => $value) {
            $found = self::valueAt($key, $value);
            if (null !== $found) {
                return $found;
            }
        }

        return null;
    }

    /**
     * The key of the platform `provider:` selects, so a configuration holding
     * several platforms is described by the one the run authenticates with;
     * with no selector the whole block is searched.
     *
     * @param array<array-key, mixed> $platform
     */
    public static function valueForProvider(array $platform, ?string $provider): ?string
    {
        if (null === $provider) {
            return self::valueIn($platform);
        }

        $providerKey = ProviderKey::of($provider);
        $block = $platform[$providerKey->platform] ?? null;
        if (\is_array($block) && null !== $providerKey->instance) {
            $block = $block[$providerKey->instance] ?? null;
        }

        return \is_array($block) ? self::valueIn($block) : null;
    }

    private static function valueAt(mixed $key, mixed $value): ?string
    {
        if (self::KEY === $key && \is_string($value) && '' !== $value) {
            return $value;
        }

        return \is_array($value) ? self::valueIn($value) : null;
    }
}
