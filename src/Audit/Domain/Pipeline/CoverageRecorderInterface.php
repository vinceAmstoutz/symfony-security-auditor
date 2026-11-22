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
 * Append-only ledger of the files each stage examined and what became of them,
 * so the report shows silent gaps.
 *
 * Statuses are plain strings. Conventional values:
 *   - attacker stage: "analyzed", "cached", "errored"
 *   - reviewer stage: "validated", "rejected", "errored"
 *   - secret_scrubbing stage: "errored" (the scrubber withheld the file's content)
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface CoverageRecorderInterface
{
    public function recordCoverage(string $stage, string $filePath, string $status): void;

    /**
     * Records a finding as soon as the reviewer reaches a verdict on it, so
     * {@see drainReviewedFindings()} recovers it when a later finding of the
     * same call aborts on a budget or provider failure.
     */
    public function recordReviewedFinding(Vulnerability $vulnerability): void;

    /**
     * Returns every finding recorded via {@see recordReviewedFinding()} since
     * the last drain and clears the buffer.
     *
     * @return list<Vulnerability>
     */
    public function drainReviewedFindings(): array;

    /**
     * Records a candidate as soon as the attacker finds it, so
     * {@see drainFoundVulnerabilities()} recovers it when a later chunk of the
     * same call aborts on a budget or provider failure. A candidate is
     * unreviewed: it still goes through the reviewer.
     */
    public function recordFoundVulnerability(Vulnerability $vulnerability): void;

    /**
     * Returns every candidate recorded via {@see recordFoundVulnerability()}
     * since the last drain and clears the buffer.
     *
     * @return list<Vulnerability>
     */
    public function drainFoundVulnerabilities(): array;
}
