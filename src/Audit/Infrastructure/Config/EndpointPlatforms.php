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
 * The `symfony/ai` platforms whose connection node declares an `endpoint`, as
 * listed by `symfony/ai-bundle`'s `config/platform/*.php`. They are the ones
 * `--endpoint` applies to, and they are distinct from the platforms naming the
 * same thing `base_url`: a platform declares one spelling or the other, never
 * both. `deepgram`, `elevenlabs` and `minimax` carry a default endpoint and
 * only need one to reach somewhere else; `ollama` declares none, so a
 * configuration without it sends the request against no base URI at all.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class EndpointPlatforms
{
    /**
     * @var list<string>
     */
    public const array NAMES = ['deepgram', 'elevenlabs', 'minimax', 'ollama'];

    /**
     * The subset whose `endpoint` node declares no default, so the bundle
     * leaves it null and the bridge has nowhere to send the request.
     *
     * @var list<string>
     */
    public const array WITHOUT_A_DEFAULT = ['ollama'];

    public static function accept(ProviderKey $providerKey): bool
    {
        return \in_array($providerKey->platform, self::NAMES, true);
    }

    public static function requires(ProviderKey $providerKey): bool
    {
        return \in_array($providerKey->platform, self::WITHOUT_A_DEFAULT, true);
    }
}
