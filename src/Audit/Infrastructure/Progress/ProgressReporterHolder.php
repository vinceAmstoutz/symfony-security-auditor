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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress;

use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Mutable delegate that wires the ProgressReporterInterface seam between
 * DI container construction time and command invocation time.
 *
 * AuditPipeline (and the DI container) receive this holder as the
 * ProgressReporterInterface implementation. AuditCommand calls setDelegate()
 * at the start of __invoke() to swap in a ConsoleProgressReporter built
 * from the live SymfonyStyle. Prior to that call the holder behaves as a
 * NullProgressReporter.
 *
 * Reporter exceptions are swallowed so a misbehaving delegate cannot abort
 * the audit (contract guarantee from ProgressReporterInterface).
 *
 * Mutable by design — non-readonly because the delegate is set after
 * construction. See .claude/rules/php-classes.md for the opt-out policy.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class ProgressReporterHolder implements ProgressReporterInterface
{
    private ProgressReporterInterface $progressReporter;

    public function __construct()
    {
        $this->progressReporter = new NullProgressReporter();
    }

    public function setDelegate(ProgressReporterInterface $progressReporter): void
    {
        $this->progressReporter = $progressReporter;
    }

    public function report(string $event, array $context = []): void
    {
        try {
            $this->progressReporter->report($event, $context);
        } catch (Throwable) {
        }
    }
}
