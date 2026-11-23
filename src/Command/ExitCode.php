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

/**
 * The exit codes of `audit:run`, whose integer values are public API.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
enum ExitCode: int
{
    case Success = 0;

    case Failure = 1;

    case BudgetAborted = 2;

    case Incomplete = 3;
}
