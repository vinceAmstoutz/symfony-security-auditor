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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception;

use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ComposerBridgeInstaller;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\CompoundPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\InstanceKeyedPlatforms;

/**
 * Replaces the "composer require" advice `AiBundle` gives for a missing bridge
 * with the command that installs it where the binary looks, or with the
 * reason a platform wrapping others cannot boot standalone. Never chains the
 * bundle's exception, whose advice the console would print too.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class ProviderBridgeException extends RuntimeException
{
    private const string MISSING_BRIDGE_PATTERN = '/requires "symfony\/ai-([a-z-]+)-platform" package/';

    public static function forBundleFailure(RuntimeException $runtimeException): ?self
    {
        if (1 !== preg_match(self::MISSING_BRIDGE_PATTERN, $runtimeException->getMessage(), $matches)) {
            return null;
        }

        $platform = ComposerBridgeInstaller::platformForSlug($matches[1]);
        $serviceNeeded = CompoundPlatforms::SERVICES_NEEDED[$platform] ?? null;
        if (null !== $serviceNeeded) {
            return new self(\sprintf(
                'The "%s" platform wraps other platforms through %s that only a Symfony application defines, so the standalone binary cannot run it. Configure the platform it wraps directly, or run the audit through the Symfony bundle.',
                $platform,
                $serviceNeeded,
            ));
        }

        $provider = \in_array($platform, InstanceKeyedPlatforms::NAMES, true) ? \sprintf('%s.<instance>', $platform) : $platform;

        return new self(\sprintf(
            'The "%1$s" provider bridge (symfony/ai-%2$s-platform) is not installed under the standalone data directory. Run "symfony-security-auditor init --provider=%3$s" to download it; a "composer require" in the audited project does not help, the binary never loads that project\'s vendor directory.',
            $platform,
            $matches[1],
            $provider,
        ));
    }
}
