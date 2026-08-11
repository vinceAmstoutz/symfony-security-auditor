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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;

/**
 * A run whose scan discovered no file at all reports SAFE, 100/100 and grade A,
 * because there was nothing to find — so a mistyped project path or a
 * `scan.included_paths` entry that matches nothing would pass any gate. That is
 * not a verdict, so it fails regardless of the thresholds. A `--since` run whose
 * diff left nothing changed still passes: there the scan did find files.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AuditExitCodeResolver implements AuditExitCodeResolverInterface
{
    #[Override]
    public function resolve(AuditReport $auditReport, RiskLevel $riskLevel, ?int $minimumScore = null): int
    {
        $failed = 0 === $auditReport->filesDiscovered()
            || $auditReport->riskLevelEnum()->isAtLeast($riskLevel)
            || $this->scoreIsBelow($auditReport, $minimumScore);

        return $failed ? ExitCode::Failure->value : ExitCode::Success->value;
    }

    private function scoreIsBelow(AuditReport $auditReport, ?int $minimumScore): bool
    {
        return null !== $minimumScore && $auditReport->normalizedScore() < $minimumScore;
    }
}
