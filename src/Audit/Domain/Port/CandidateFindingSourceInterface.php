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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/** @internal not part of the BC promise — see docs/versioning.md */
interface CandidateFindingSourceInterface
{
    /**
     * Findings found deterministically, without a model, that the reviewer
     * still has to validate or reject.
     *
     * @param list<ProjectFile> $files
     *
     * @return list<Vulnerability>
     */
    public function candidatesIn(array $files): array;
}
