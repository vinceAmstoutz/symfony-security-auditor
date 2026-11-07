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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;

/**
 * The coverage critic of a run that leaves `audit.coverage_critic` off: it
 * names no gap and spends no call.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NullCoverageCritic implements CoverageCriticInterface
{
    #[Override]
    public function gaps(SymfonyMapping $symfonyMapping, AuditContext $auditContext): array
    {
        return [];
    }
}
