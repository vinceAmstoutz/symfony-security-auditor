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

namespace VinceAmstoutz\SecurityAuditor\Command;

/**
 * The process exit codes of `audit:run`. The integer VALUES are public API
 * (see docs/versioning.md); this enum is the internal source of truth for them.
 *
 * `Failure` means the audit reached a verdict and the gate tripped on it;
 * `AuditFailed` means no verdict was reached — the run broke, or its scan found
 * nothing to examine. Keeping them apart is the whole point of the split: a
 * crashed or misconfigured auditor must not look like a working one reporting
 * real vulnerabilities.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
enum ExitCode: int
{
    case Success = 0;

    case Failure = 1;

    case BudgetAborted = 2;

    case AuditFailed = 3;
}
