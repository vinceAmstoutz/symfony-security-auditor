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
 * One-way channel for the progress events of a running audit, each a short
 * identifier with an optional context payload. Implementations MUST NOT
 * throw: a reporter failure must never abort the audit.
 */
interface ProgressReporterInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function report(string $event, array $context = []): void;
}
