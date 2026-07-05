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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/**
 * Opt-in extension of {@see ReportRendererInterface} for formats that render
 * baselined findings instead of dropping them, marking each as suppressed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface BaselineSuppressingReportRendererInterface
{
    /**
     * @param list<string> $baselinedFingerprints
     */
    public function renderWithSuppressions(AuditReport $auditReport, array $baselinedFingerprints): string;
}
