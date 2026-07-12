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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception;

use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/**
 * Common shape of every exception that halts an audit mid-run while still
 * carrying a partial `AuditReport` — implemented by
 * {@see AuditAbortedByBudgetException} and {@see AuditAbortedByProviderException}
 * so the command layer can render whatever findings were validated before
 * the abort with a single catch site, regardless of the abort's cause.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface AuditAbortedExceptionInterface extends Throwable
{
    public function partialReport(): AuditReport;
}
