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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
interface AttackerAgentInterface
{
    /**
     * @param ProjectFile[]   $files
     * @param bool            $bypassCache      when true, the agent must skip both
     *                                          reads from and writes to the
     *                                          `AttackerCacheInterface` for this call
     * @param Vulnerability[] $previousFindings findings already validated by the
     *                                          reviewer in earlier iterations.
     *                                          The agent injects a compact pattern
     *                                          summary into the prompt so the LLM
     *                                          generalizes them to files not yet
     *                                          covered instead of re-discovering
     *                                          the same bugs at the same lines.
     *
     * @return Vulnerability[]
     */
    public function analyze(array $files, SymfonyMapping $symfonyMapping, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false, array $previousFindings = []): array;
}
