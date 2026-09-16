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

/**
 * Every symfony/ai platform that authenticates spells its credential
 * `api_key`, whichever provider it is, so one lookup serves them all.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformApiKey
{
    private const string KEY = 'api_key';

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

    private static function valueAt(mixed $key, mixed $value): ?string
    {
        if (self::KEY === $key && \is_string($value) && '' !== $value) {
            return $value;
        }

        return \is_array($value) ? self::valueIn($value) : null;
    }
}
