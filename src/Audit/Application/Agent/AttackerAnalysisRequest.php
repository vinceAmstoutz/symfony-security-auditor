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

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Immutable input bundle for a single attacker analysis pass. Collapses what
 * were five positional parameters into one value object so callers (the
 * orchestrator, the escalating agent) read clearly and new context can be
 * added without churning every call site.
 */
final readonly class AttackerAnalysisRequest
{
    /**
     * @param list<ProjectFile>   $files
     * @param list<Vulnerability> $previousFindings  findings already validated by the
     *                                               reviewer in earlier iterations, injected
     *                                               into the prompt so the LLM generalizes
     *                                               them to files not yet covered
     * @param list<Vulnerability> $rejectedFindings  findings the reviewer rejected in earlier
     *                                               iterations, injected so the LLM stops
     *                                               re-reporting them (saving tool-call and
     *                                               reviewer budget)
     * @param list<Vulnerability> $candidateFindings findings a cheaper first-pass model reported on
     *                                               these files, injected so the LLM confirms,
     *                                               refines or discards each one — unlike
     *                                               previousFindings they are unvalidated and
     *                                               must be re-reported when confirmed
     * @param ?list<ProjectFile>  $toolFiles         the files the investigation tools may open when they
     *                                               are not the files to analyze — every scanned file on a
     *                                               run narrowed by `--since`, `--path` or the escalation
     *                                               deep pass, with `audit.tools_scope: scanned`; null
     *                                               means `files`, those of the deep pass included
     */
    public function __construct(
        public array $files,
        public SymfonyMapping $symfonyMapping,
        public bool $bypassCache = false,
        public array $previousFindings = [],
        public array $rejectedFindings = [],
        public array $candidateFindings = [],
        public ?array $toolFiles = null,
    ) {}

    /**
     * @return list<ProjectFile>
     */
    public function filesForTools(): array
    {
        return $this->toolFiles ?? $this->files;
    }

    /**
     * @param list<ProjectFile>   $files
     * @param list<Vulnerability> $candidateFindings
     */
    public function withFilesAndCandidateFindings(array $files, array $candidateFindings): self
    {
        return new self($files, $this->symfonyMapping, $this->bypassCache, $this->previousFindings, $this->rejectedFindings, $candidateFindings, $this->toolFiles);
    }
}
