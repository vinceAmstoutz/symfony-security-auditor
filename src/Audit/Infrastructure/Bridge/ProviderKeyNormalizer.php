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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\ConfigKeyInstanceName;

use function Symfony\Component\String\u;

/**
 * Folds a provider as typed to its `symfony/ai` platform config key: a
 * bridge slug such as `open-ai` becomes `openai`, the platform is lowercased
 * and an instance name is folded as `symfony/config` folds it.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProviderKeyNormalizer
{
    public function normalize(string $provider): string
    {
        $providerKey = ProviderKey::of(u($provider)->trim()->toString());
        $platformKey = u($providerKey->platform)->lower()->toString();
        $platform = array_flip(ComposerBridgeInstaller::PACKAGE_SLUG_OVERRIDES)[$platformKey] ?? $platformKey;

        if (null === $providerKey->instance) {
            return $platform;
        }

        return $platform.ProviderKey::INSTANCE_SEPARATOR.ConfigKeyInstanceName::of($providerKey->instance);
    }
}
