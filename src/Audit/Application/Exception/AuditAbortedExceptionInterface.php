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
 * An exception that halts an audit mid-run and carries the partial
 * `AuditReport` of what was validated before the abort.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface AuditAbortedExceptionInterface extends Throwable
{
    public function partialReport(): AuditReport;
}
