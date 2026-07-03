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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use Override;

/** @internal default when no security-config parser is wired — extracts nothing */
final readonly class NullSecurityConfigParser implements SecurityConfigParserInterface
{
    #[Override]
    public function parseAccessControl(string $configContent): array
    {
        return [];
    }

    #[Override]
    public function parseFirewallRules(string $configContent): array
    {
        return [];
    }
}
