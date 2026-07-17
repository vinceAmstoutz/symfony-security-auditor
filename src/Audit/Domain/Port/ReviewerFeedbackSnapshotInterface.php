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
 * Discards any per-run memoized reviewer-feedback snapshot at the start of a
 * new audit run. A long-lived process (e.g. `mcp:serve`) reuses the same
 * container across audits, so a provider that freezes its feedback set for the
 * duration of one run must be told when the next run begins — otherwise every
 * audit after the first serves the first run's stale feedback.
 */
interface ReviewerFeedbackSnapshotInterface
{
    public function resetForNewRun(): void;
}
