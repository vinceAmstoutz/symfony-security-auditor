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

use function Symfony\Component\String\u;

/**
 * Folds a user-supplied provider spelling back to the `symfony/ai` platform
 * config key the rest of the stack expects: trims and lowercases the input and
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
        $configKey = u($provider)->trim()->lower()->toString();

        return array_flip(ComposerBridgeInstaller::PACKAGE_SLUG_OVERRIDES)[$configKey] ?? $configKey;
    }
}
