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
 * listed by `symfony/ai-bundle`'s `config/platform/*.php`. Taking a `base_url`
 * and being instance keyed are independent: `azure`, `generic` and
 * `openresponses` are both, while `albert` and `amazeeai` require a `base_url`
 * on a flat block, and `bedrock`, `cache` and `failover` are instance keyed
 * with no `base_url` at all. Every other platform names its endpoint
 * differently (`ollama` uses `endpoint`, `lmstudio` uses `host_url`) or hosts
 * no endpoint of its own.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BaseUrlPlatforms
{
    /**
     * @var list<string>
     */
    public const array NAMES = ['albert', 'amazeeai', 'azure', 'generic', 'openresponses'];

    public static function accept(ProviderKey $providerKey): bool
    {
        return \in_array($providerKey->platform, self::NAMES, true);
    }

    /**
     * The subset `init` can actually write, for the messages that tell a user
     * where `--base-url` belongs: `azure` declares a `base_url` but is refused
     * earlier for needing a `deployment`, so naming it only sends them into a
     * second refusal.
     *
     * @return list<string>
     */
    public static function writableNames(): array
    {
        return array_values(array_diff(self::NAMES, array_keys(HandWrittenPlatforms::REQUIREMENTS)));
    }

    /**
     * The same platforms, spelled the way a provider that works spells them, so
     * a reader told `--base-url` does not apply to theirs is not handed a name
     * that would be refused again for naming no instance.
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
