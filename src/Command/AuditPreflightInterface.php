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
 * Assembles the audit command as `audit` does at startup, without running it.
 * `failureReason()` says why it fails to boot, null when it boots.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface AuditPreflightInterface
{
    public function failureReason(): ?string;
}
