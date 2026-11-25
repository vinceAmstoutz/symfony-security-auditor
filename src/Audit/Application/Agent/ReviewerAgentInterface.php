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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/** @internal not part of the BC promise, see docs/versioning.md */
interface ReviewerAgentInterface
{
    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     * @param ?list<ProjectFile>  $toolFiles       the files the investigation tools may open and a finding in
     *                                             them is reviewed against, when not the audited files; null
     *                                             means `$projectFiles`
     *
     * @return list<Vulnerability>
     */
    public function review(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false, ?array $toolFiles = null): array;

    /**
     * Reviews each finding with the others of its file in one call, so the
     * file is sent once per call.
     *
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     * @param ?list<ProjectFile>  $toolFiles       as {@see self::review()} takes them
     *
     * @return list<Vulnerability>
     */
    public function reviewByFile(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false, ?array $toolFiles = null): array;
}
