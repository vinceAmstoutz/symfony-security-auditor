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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\History;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AuditHistoryStoreInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class NullAuditHistoryStore implements AuditHistoryStoreInterface
{
    public function loadFingerprints(string $projectIdentifier): array
    {
        return [];
    }

    public function storeFingerprints(string $projectIdentifier, array $fingerprints): void
    {
        // Intentionally a no-op — historical correlation is disabled.
    }
}
