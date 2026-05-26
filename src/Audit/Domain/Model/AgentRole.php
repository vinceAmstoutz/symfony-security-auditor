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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/** @internal not part of the BC promise — the enum *values* (`attacker`, `reviewer`) are stable identifiers carried in `CoverageRecorderInterface::recordCoverage()` stage labels and in the cost-by-role keys of the JSON/SARIF report schema, but the PHP enum itself is for internal use only. */
enum AgentRole: string
{
    case Attacker = 'attacker';
    case Reviewer = 'reviewer';
}
