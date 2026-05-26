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
 * Cross-run persistence for the set of fingerprints surfaced by the previous
 * audit of a given project. Drives the `new / still_present / fixed`
 * correlation that lets dashboards and PR comments show remediation progress.
 *
 * Implementations MUST be idempotent on `store()` — calling it twice with the
 * same project + fingerprints overwrites cleanly. Failures to load (missing
 * file, parse error) MUST return an empty list rather than throwing — the
 * first audit of a brand-new project is the normal state.
 */
interface AuditHistoryStoreInterface
{
    /**
     * @return list<string> fingerprints surfaced by the project's previous audit,
     *                      or [] when no prior run was recorded
     */
    public function loadFingerprints(string $projectIdentifier): array;

    /**
     * @param list<string> $fingerprints fingerprints to record as the project's latest audit
     */
    public function storeFingerprints(string $projectIdentifier, array $fingerprints): void;
}
