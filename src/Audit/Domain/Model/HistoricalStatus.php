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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * Cross-run status of a finding relative to the project's previous audit.
 *
 * Stable across line-number drift because it is computed against
 * `Vulnerability::fingerprint()`, not `Vulnerability::id()`.
 *
 * `New`           — this is the first audit to surface the finding.
 * `StillPresent`  — the previous audit found the same thing; the project did not remediate it yet.
 * `Unknown`       — historical correlation was disabled or no previous audit exists.
 *
 * `Fixed` is intentionally absent: findings that disappeared between runs are
 * reported via `AuditContext.meta['audit.history.fixed']` (a count + list of
 * fingerprints), not as ghost-Vulnerability instances.
 */
enum HistoricalStatus: string
{
    case New = 'new';
    case StillPresent = 'still_present';
    case Unknown = 'unknown';
}
