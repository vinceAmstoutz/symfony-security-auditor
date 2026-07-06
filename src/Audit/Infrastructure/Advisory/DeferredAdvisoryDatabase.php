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
 * memoizing the result across the rest of the run.
 *
 * `ComposerAuditAdvisoryDatabase` is `final readonly`, so it cannot be a
 * Symfony `->lazy()` service: proxy generation requires either a native PHP
 * 8.4+ lazy ghost (this project supports 8.3+) or a subclassing proxy, and
 * neither works for a final readonly class. This hand-rolled wrapper achieves
 * the same goal — `AuditedProjectPathHolder::path()` must not be read before
 * `AuditCommand` sets it — without relying on proxy generation.
 *
 * Not readonly: it memoizes the inner database on first use (stateful
 * collaborator carve-out — same shape as `AuditedProjectPathHolder`).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class DeferredAdvisoryDatabase implements AdvisoryDatabaseInterface
{
    private ?AdvisoryDatabaseInterface $advisoryDatabase = null;

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

    private function innerDatabase(): AdvisoryDatabaseInterface
    {
        return $this->advisoryDatabase ??= new ComposerAuditAdvisoryDatabase($this->composerAuditRunner, $this->auditedProjectPathHolder, $this->logger);
    }
}
