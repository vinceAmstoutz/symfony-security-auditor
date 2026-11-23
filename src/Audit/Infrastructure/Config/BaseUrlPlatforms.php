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
 * The `symfony/ai` platforms whose connection node declares a `base_url`, as
 * `symfony/ai-bundle`'s `config/platform/*.php` lists them.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class BaseUrlPlatforms
{
    /**
     * @var list<string>
     */
    public const array NAMES = ['albert', 'amazeeai', 'azure', 'generic', 'higgsfield', 'openresponses'];

    public static function accept(ProviderKey $providerKey): bool
    {
        return \in_array($providerKey->platform, self::NAMES, true);
    }

    /**
     * Returns the subset `init` writes, leaving out the hand-written ones such
     * as `azure`.
     *
     * @return list<string>
     */
    public static function writableNames(): array
    {
        return array_values(array_diff(self::NAMES, array_keys(HandWrittenPlatforms::REQUIREMENTS)));
    }

    /**
     * Returns the same platforms as a provider spells them, with an
     * `<instance>` for an instance-keyed one.
     *
     * @return list<string>
     */
    public static function writableShapes(): array
    {
        $shapes = [];

        foreach (self::writableNames() as $platform) {
            $shapes[] = \in_array($platform, InstanceKeyedPlatforms::NAMES, true) ? \sprintf('%s.<instance>', $platform) : $platform;
        }

        return $shapes;
    }
}
