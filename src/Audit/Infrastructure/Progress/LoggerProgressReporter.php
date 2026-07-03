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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Forwards each progress event to a PSR-3 logger at info level under the
 * `audit.progress` message prefix. Useful for hosts that already collect
 * structured logs (e.g. monolog → ELK) and want progress visibility
 * without wiring custom infrastructure.
 *
 * Logger failures are swallowed so a misbehaving logger cannot abort the
 * audit (contract guarantee from the ProgressReporterInterface).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LoggerProgressReporter implements ProgressReporterInterface
{
    public function __construct(private LoggerInterface $logger) {}

    #[Override]
    public function report(string $event, array $context = []): void
    {
        try {
            $this->logger->info(\sprintf('audit.progress: %s', $event), $context);
        } catch (Throwable $throwable) {
            error_log(\sprintf('LoggerProgressReporter could not forward progress event "%s": %s', $event, $throwable->getMessage()));
        }
    }
}
