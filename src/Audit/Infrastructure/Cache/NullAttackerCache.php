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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class NullAttackerCache implements AttackerCacheInterface
{
    public function get(array $chunk): ?array
    {
        return null;
    }

    public function store(array $chunk, array $rawVulnerabilities): void
    {
        // intentionally noop
    }
}
