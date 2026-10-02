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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Opt-in companion of {@see CoverageRecorderInterface} for a recorder that
 * keeps the findings the reviewer rejected — a verdict it reached, unlike a
 * review that failed and reached none — so a later attacker iteration is told
 * only about the findings the reviewer actually dismissed. The reviewer checks
 * for it with `instanceof`, so a recorder without it keeps working.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface RejectedFindingRecorderInterface
{
    public function recordRejectedFinding(Vulnerability $vulnerability): void;
}
