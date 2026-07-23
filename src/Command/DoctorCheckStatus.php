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

/** @internal not part of the BC promise — the command *name* (`doctor`) is public, but this enum is for internal use only. */
enum DoctorCheckStatus
{
    case Ok;

    case Warning;

    case Failure;
}
