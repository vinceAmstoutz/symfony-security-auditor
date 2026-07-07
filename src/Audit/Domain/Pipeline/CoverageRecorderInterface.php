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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Append-only coverage tracker. Agents call this to declare which files they
 * examined and what happened. Surfaces silent gaps in the report (a file the
 * attacker never reached, a reviewer error on an otherwise valid finding, …).
 *
 * Statuses are plain strings to keep the port stable when new outcomes are added.
 * Conventional values:
 *   - attacker stage: "analyzed", "cached", "errored"
 *   - reviewer stage: "validated", "rejected", "errored"
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface CoverageRecorderInterface
{
    public function recordCoverage(string $stage, string $filePath, string $status): void;

    /**
     * Records a finding the reviewer has actually reached a verdict for
     * (validated or rejected), at the moment that verdict is produced —
     * separately from the reviewer's own return value, which a caller only
     * receives once every finding in the batch has been processed. If a
     * later finding in the same call aborts with a budget/provider
     * exception, that return value never materializes; this side channel
     * lets the caller recover verdicts already reached before the abort via
     * {@see drainReviewedFindings()} instead of losing them.
     */
    public function recordReviewedFinding(Vulnerability $vulnerability): void;

    /**
     * Returns every finding recorded via {@see recordReviewedFinding()} since
     * the last drain, and clears the buffer.
     *
     * @return list<Vulnerability>
     */
    public function drainReviewedFindings(): array;
}
