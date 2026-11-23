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
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AttackerAnalysisRequest
{
    private KnownFiles $knownFiles;

    /**
     * @param list<ProjectFile>   $files
     * @param list<Vulnerability> $previousFindings  findings the reviewer validated in earlier
     *                                               iterations, for the LLM to generalize
     * @param list<Vulnerability> $rejectedFindings  findings the reviewer rejected in earlier
     *                                               iterations, for the LLM to stop re-reporting
     * @param list<Vulnerability> $candidateFindings unvalidated findings a cheaper first pass
     *                                               reported on these files, for the LLM to
     *                                               confirm by re-reporting, refine or discard
     * @param ?list<ProjectFile>  $toolFiles         the files the investigation tools may open
     *                                               when they are not `files` (every scanned
     *                                               file under `audit.tools_scope: scanned`);
     *                                               null means `files`
     */
    public function __construct(
        public array $files,
        public SymfonyMapping $symfonyMapping,
        public bool $bypassCache = false,
        public array $previousFindings = [],
        public array $rejectedFindings = [],
        public array $candidateFindings = [],
        public ?array $toolFiles = null,
    ) {
        $this->knownFiles = new KnownFiles($this->filesForTools());
    }

    /**
     * @return list<ProjectFile>
     */
    public function filesForTools(): array
    {
        return $this->toolFiles ?? $this->files;
    }

    /**
     * Returns the files a finding on `$chunk` may be named by: the chunk's own
     * first, then every file the investigation tools may open.
     *
     * @param list<ProjectFile> $chunk
     */
    public function knownFilesFor(array $chunk): KnownFiles
    {
        return new KnownFiles($chunk, $this->knownFiles);
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
