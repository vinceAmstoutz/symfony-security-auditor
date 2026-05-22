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

/**
 * Append-only coverage tracker. Agents call this to declare which files they
 * examined and what happened. Surfaces silent gaps in the report (a file the
 * attacker never reached, a reviewer error on an otherwise valid finding, …).
 *
 * Statuses are plain strings to keep the port stable when new outcomes are added.
 * Conventional values:
 *   - attacker stage: "analyzed", "cached", "errored"
 *   - reviewer stage: "validated", "rejected", "errored"
 */
interface CoverageRecorderInterface
{
    public function recordCoverage(string $stage, string $filePath, string $status): void;
}
