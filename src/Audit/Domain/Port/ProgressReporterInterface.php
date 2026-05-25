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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

/**
 * One-way channel for emitting progress events while an audit is running.
 *
 * Implementations are responsible for *displaying* progress (CLI write,
 * log line, SSE event, …); the pipeline and orchestrator never inspect
 * the destination, they just emit events. The default implementation
 * (`NullProgressReporter`) discards everything — wire a real reporter
 * (e.g. `LoggerProgressReporter`) to surface progress to users.
 *
 * Events are keyed by a short snake_case identifier; the (optional)
 * context array carries event-specific payload (audit id, stage name,
 * iteration number, …). Implementations MUST NOT throw — a reporter
 * failure must never abort the audit.
 */
interface ProgressReporterInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function report(string $event, array $context = []): void;
}
