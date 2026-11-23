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

use Override;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Delegates to the reporter `AuditCommand` sets, a NullProgressReporter until
 * then. A delegate's exception never aborts the audit.
 *
 * Not readonly: the delegate is set after construction (see
 * .claude/rules/php-classes.md).
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class ProgressReporterHolder implements ProgressReporterInterface
{
    private ProgressReporterInterface $progressReporter;

    public function __construct(private readonly LoggerInterface $logger)
    {
        $this->progressReporter = new NullProgressReporter();
    }

    public function setDelegate(ProgressReporterInterface $progressReporter): void
    {
        $this->progressReporter = $progressReporter;
    }

    #[Override]
    public function report(string $event, array $context = []): void
    {
        try {
            $this->progressReporter->report($event, $context);
        } catch (Throwable $throwable) {
            $this->logFailure($event, $throwable);
        }
    }

    private function logFailure(string $event, Throwable $throwable): void
    {
        try {
            $this->logger->debug('Progress reporter failed; audit continues.', [
                'event' => $event,
                'exception' => $throwable,
            ]);
        } catch (Throwable $loggerThrowable) {
            error_log(\sprintf('ProgressReporterHolder could not log a failed progress event "%s": %s', $event, $loggerThrowable->getMessage()));
        }
    }
}
