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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;

/**
 * Names the entry points or sibling paths no attacker chunk showed together,
 * once the attacker/reviewer loop is over.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface CoverageCriticInterface
{
    /**
     * @return list<CoverageGap>
     */
    public function gaps(SymfonyMapping $symfonyMapping, AuditContext $auditContext): array;
}
