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
 * Attempts to assemble the audit command exactly the way `audit` does at
 * startup, without running it, so a preflight can report why an audit would
 * fail to boot before one is attempted.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface AuditPreflightInterface
{
    public function failureReason(): ?string;
}
