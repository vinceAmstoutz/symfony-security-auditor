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

/**
 * Why `init` cannot write the deployment it was given: Azure OpenAI needs
 * one, and no other platform takes one.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class DeploymentRefusal
{
    public static function of(ProviderKey $providerKey, string $provider, ?string $deployment): ?string
    {
        if ('azure' !== $providerKey->platform) {
            return null === $deployment ? null : \sprintf('--deployment applies to Azure OpenAI (azure.<instance>) only; "%s" has no deployment.', $provider);
        }

        return null === $deployment || '' === $deployment
            ? \sprintf('"%s" needs the name of its deployment, so nothing was written. Re-run with --deployment=<name>.', $provider)
            : null;
    }
}
