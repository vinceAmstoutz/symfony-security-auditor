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
 * Finds the `api_key` every authenticating symfony/ai platform spells its
 * credential with.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
     * Returns the key of the platform `provider:` selects, searching the whole
     * block when no provider is set.
     *
     * @param array<array-key, mixed> $platform
     */
    public static function valueForProvider(array $platform, ?string $provider): ?string
    {
        $block = self::blockForProvider($platform, $provider);

        return null !== $block ? self::valueIn($block) : null;
    }

    /**
     * Returns the block of the platform `provider:` selects, the whole block
     * when no provider is set, or null when the selected one is not configured;
     * a block written with no value is an empty one.
     *
     * @param array<array-key, mixed> $platform
     *
     * @return ?array<array-key, mixed>
     */
    public static function blockForProvider(array $platform, ?string $provider): ?array
    {
        if (null === $provider) {
            return $platform;
        }

        $providerKey = ProviderKey::of($provider);
        $block = self::configuredBlock($platform, $providerKey->platform);
        if (\is_array($block) && null !== $providerKey->instance) {
            $block = self::configuredBlock($block, $providerKey->instance);
        }

        return \is_array($block) ? $block : null;
    }

    /**
     * Reads a block written with no value (`claudecode:` or `claudecode: ~`)
     * as an empty map.
     *
     * @param array<array-key, mixed> $map
     */
    private static function configuredBlock(array $map, string $key): mixed
    {
        return \array_key_exists($key, $map) ? $map[$key] ?? [] : null;
    }

    private static function valueAt(mixed $key, mixed $value): ?string
    {
        if (self::KEY === $key && \is_string($value) && '' !== $value) {
            return $value;
        }

        return \is_array($value) ? self::valueIn($value) : null;
    }
}
