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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use Override;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;

/**
 * Builds {@see ComposerAuditAdvisoryDatabase} (which runs `composer audit`) on
 * the first {@see self::lookup()}: `AuditedProjectPathHolder::path()` is not
 * read before `AuditCommand` sets it. Builds it again once the holder's path or
 * the project's `composer.lock` changes, after
 * `LockfileHashedAdvisoryCache::TTL_SECONDS`, or after
 * `FAILED_LOAD_RETRY_SECONDS` when the load failed.
 *
 * Not readonly: memoizes the inner database (stateful collaborator, see
 * .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class DeferredAdvisoryDatabase implements AdvisoryDatabaseInterface
{
    private const int FAILED_LOAD_RETRY_SECONDS = 300;

    private ?AdvisorySnapshot $advisorySnapshot = null;

    public function __construct(
        private readonly ComposerAuditRunnerInterface $composerAuditRunner,
        private readonly AuditedProjectPathHolder $auditedProjectPathHolder,
        private readonly LoggerInterface $logger,
        private readonly LockfileHasher $lockfileHasher,
        private readonly ClockInterface $clock,
    ) {}

    #[Override]
    public function lookup(string $packageName, string $installedVersion): array
    {
        return $this->innerDatabase()->lookup($packageName, $installedVersion);
    }

    private function innerDatabase(): AdvisoryDatabaseInterface
    {
        $snapshotKey = $this->snapshotKey();
        $now = $this->clock->now()->getTimestamp();
        if ($this->advisorySnapshot instanceof AdvisorySnapshot && $this->advisorySnapshot->serves($snapshotKey, $now)) {
            return $this->advisorySnapshot->composerAuditAdvisoryDatabase;
        }

        $composerAuditAdvisoryDatabase = new ComposerAuditAdvisoryDatabase($this->composerAuditRunner, $this->auditedProjectPathHolder, $this->logger);
        $this->advisorySnapshot = new AdvisorySnapshot($snapshotKey, $composerAuditAdvisoryDatabase, $now + ($composerAuditAdvisoryDatabase->hasFailedToLoad() ? self::FAILED_LOAD_RETRY_SECONDS : LockfileHashedAdvisoryCache::TTL_SECONDS));

        return $composerAuditAdvisoryDatabase;
    }

    private function snapshotKey(): string
    {
        $projectPath = $this->auditedProjectPathHolder->path();

        return \sprintf("%s\0%s", $projectPath, $this->lockfileHasher->hash($projectPath) ?? '');
    }
}
