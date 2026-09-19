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
 * Folds a user-supplied provider spelling back to the `symfony/ai` platform
 * config key the rest of the stack expects: trims the input, lowercases the
 * platform half, folds an instance name the way `symfony/config` will, and
 * maps the hyphenated bridge package slugs (`open-ai`, `deep-seek`, …) to their
 * config keys (`openai`, `deepseek`). Without this, `init --provider=open-ai`
 * installs a real bridge package but writes a platform key no container can
 * ever boot from.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
