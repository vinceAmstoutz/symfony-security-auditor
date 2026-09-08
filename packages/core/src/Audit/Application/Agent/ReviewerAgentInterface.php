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

namespace VinceAmstoutz\SecurityAuditor\Audit\Application\Agent;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
interface ReviewerAgentInterface
{
    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    public function review(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false): array;
}
