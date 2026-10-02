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
 * The one sentence every human-facing renderer shows in place of its "no
 * vulnerabilities found" line when some file could not be fully analyzed, so no format
 * can present an aborted or partly failed run as a clean result. A run that
 * made no LLM call at all — a dry run, or one stopped before its first call —
 * names no failed file, so it says that none was analyzed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class IncompleteAuditNotice
{
    public static function for(AuditReport $auditReport): ?string
    {
        if ($auditReport->isComplete()) {
            return null;
        }

        $unanalyzed = \count($auditReport->unanalyzedFiles());

        return 0 === $unanalyzed
            ? \sprintf('Audit incomplete: none of the %d file(s) in scope was analyzed, because no LLM call was made or the run stopped before its first one, so this report cannot vouch that the project is free of vulnerabilities.', $auditReport->filesScanned())
            : \sprintf('Audit incomplete: %d file(s) could not be fully analyzed because an LLM call failed or the run was aborted, so this report cannot vouch that the project is free of vulnerabilities.', $unanalyzed);
    }
}
