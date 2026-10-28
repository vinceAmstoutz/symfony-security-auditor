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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\InstanceKeyedPlatforms;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\PlatformCatalogProviders;

/**
 * The providers `init` lists to pick from: the platforms the pricing catalog
 * prices that a bare name configures, so a pick always prices the run.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class InitProviderChoices
{
    /**
     * @return list<string>
     */
    public static function names(): array
    {
        $names = array_values(array_diff(array_keys(PlatformCatalogProviders::PROVIDERS), InstanceKeyedPlatforms::NAMES));
        sort($names);

        return $names;
    }
}
