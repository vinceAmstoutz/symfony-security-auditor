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

/**
 * Outcome of applying a baseline: the (possibly filtered) report and how many
 * findings the baseline suppressed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BaselineResult
{
    public function __construct(
        public AuditReport $report,
        public int $suppressedCount,
    ) {}
}
