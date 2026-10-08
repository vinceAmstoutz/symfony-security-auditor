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
 * Defers constructing {@see ComposerAuditAdvisoryDatabase} — and therefore
 * running `composer audit` — until the first {@see self::lookup()} call,
 * memoizing the result for as long as the holder's path and the content of the
 * project's `composer.lock` stay unchanged. A load that failed is memoized for
 * `FAILED_LOAD_RETRY_SECONDS` only: a timeout is not paid again on every
 * lookup, and a transient failure does not silence the lookup for good.
 *
 * `ComposerAuditAdvisoryDatabase` is `final readonly`, so it cannot be a
 * Symfony `->lazy()` service: proxy generation requires either a native PHP
 * 8.4+ lazy ghost (this project supports 8.3+) or a subclassing proxy, and
 * neither works for a final readonly class. This hand-rolled wrapper achieves
 * the same goal — `AuditedProjectPathHolder::path()` must not be read before
 * `AuditCommand` sets it — without relying on proxy generation.
 *
 * Not readonly: it memoizes the inner database on first use, and rebuilds it
 * whenever the holder is re-targeted to a different project or the lockfile is
 * rewritten — a service instance reused across two audits (`mcp:serve`) must
 * not keep serving a stale snapshot (stateful collaborator carve-out — same
 * shape as `AuditedProjectPathHolder`).
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
        $this->advisorySnapshot = new AdvisorySnapshot($snapshotKey, $composerAuditAdvisoryDatabase, $composerAuditAdvisoryDatabase->hasFailedToLoad() ? $now + self::FAILED_LOAD_RETRY_SECONDS : null);

        return $composerAuditAdvisoryDatabase;
    }

    /**
     * Otherwise a service instance reused across a second audit of a
     * different project, or of the same project after `composer update`,
     * would keep serving the first `composer audit` snapshot.
     */
    private function snapshotKey(): string
    {
        $projectPath = $this->auditedProjectPathHolder->path();

        return \sprintf("%s\0%s", $projectPath, $this->lockfileHasher->hash($projectPath) ?? '');
    }
}
