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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Stage\Fixture;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AuditHistoryStoreInterface;

/**
 * Test fake: an in-memory AuditHistoryStoreInterface that returns a fixed
 * "previous run" fingerprint set and records what the stage persisted, so
 * tests can assert correlation behaviour without touching the filesystem.
 */
final class RecordingAuditHistoryStore implements AuditHistoryStoreInterface
{
    /** @var list<string> */
    public array $stored = [];

    /**
     * @param list<string> $previous
     */
    public function __construct(
        private readonly array $previous = [],
    ) {}

    public function loadFingerprints(string $projectIdentifier): array
    {
        return $this->previous;
    }

    public function storeFingerprints(string $projectIdentifier, array $fingerprints): void
    {
        $this->stored = $fingerprints;
    }
}
