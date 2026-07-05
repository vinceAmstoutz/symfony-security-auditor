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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/** @internal not part of the BC promise — see docs/versioning.md */
interface BaselineProcessorInterface
{
    /**
     * Writes the report's finding fingerprints to a baseline file and returns
     * how many were written.
     */
    public function generate(AuditReport $auditReport, string $path): int;

    /**
     * Fingerprints of accepted findings from the effective baseline file,
     * resolving the CLI `--baseline` override against the configured default
     * path. Empty when neither is set.
     *
     * @return list<string>
     */
    public function acceptedFingerprints(?string $cliBaseline): array;

    /**
     * Suppresses baselined findings from the report, resolving the CLI
     * `--baseline` override against the configured default path. When no path
     * is set, the report is returned unchanged with a zero suppressed count.
     * The returned {@see BaselineResult} also carries the matched fingerprints
     * so callers can render suppressed findings instead of dropping them.
     */
    public function apply(AuditReport $auditReport, ?string $cliBaseline): BaselineResult;
}
