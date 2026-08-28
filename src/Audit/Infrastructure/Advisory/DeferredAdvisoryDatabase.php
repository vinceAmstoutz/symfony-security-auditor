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
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;

/**
 * Defers constructing {@see ComposerAuditAdvisoryDatabase} — and therefore
 * running `composer audit` — until the first {@see self::lookup()} call,
 * memoizing the result for as long as the holder's path stays unchanged.
 *
 * `ComposerAuditAdvisoryDatabase` is `final readonly`, so Symfony `->lazy()`
 * cannot proxy it: that needs a native 8.4+ lazy ghost (this project supports
 * 8.3) or a subclass. Hence the hand-rolled wrapper — the holder's path must
 * not be read before `AuditCommand` sets it.
 *
 * Not readonly: it rebuilds whenever the holder is re-targeted, so an instance
 * reused across two audits never serves the first project's snapshot.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class DeferredAdvisoryDatabase implements AdvisoryDatabaseInterface
{
    private ?AdvisoryDatabaseInterface $advisoryDatabase = null;

    private ?string $memoizedProjectPath = null;

    public function __construct(
        private readonly ComposerAuditRunnerInterface $composerAuditRunner,
        private readonly AuditedProjectPathHolder $auditedProjectPathHolder,
        private readonly LoggerInterface $logger,
    ) {}

    #[Override]
    public function lookup(string $packageName, string $installedVersion): array
    {
        return $this->innerDatabase()->lookup($packageName, $installedVersion);
    }

    /**
     * Rebuilds the inner database whenever the holder's path has moved since
     * the last lookup — otherwise a service instance reused across a second
     * audit of a different project would keep serving the first project's
     * stale `composer audit` snapshot.
     */
    private function innerDatabase(): AdvisoryDatabaseInterface
    {
        $currentProjectPath = $this->auditedProjectPathHolder->path();
        if (!$this->advisoryDatabase instanceof AdvisoryDatabaseInterface || $currentProjectPath !== $this->memoizedProjectPath) {
            $this->advisoryDatabase = new ComposerAuditAdvisoryDatabase($this->composerAuditRunner, $this->auditedProjectPathHolder, $this->logger);
            $this->memoizedProjectPath = $currentProjectPath;
        }

        return $this->advisoryDatabase;
    }
}
