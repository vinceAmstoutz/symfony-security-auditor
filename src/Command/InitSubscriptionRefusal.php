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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CliAgentPlatforms;

/**
 * Why `init` refuses an option a subscription has no use for, or null.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class InitSubscriptionRefusal
{
    public static function forApiKeyVariable(ProviderKey $providerKey, string $provider, ?string $envVar): ?string
    {
        return null !== $envVar && CliAgentPlatforms::declares($providerKey)
            ? \sprintf('--env-var names the variable an API key is read from, but "%s" runs on a subscription, which takes no API key. Leave --env-var out.', $provider)
            : null;
    }
}
