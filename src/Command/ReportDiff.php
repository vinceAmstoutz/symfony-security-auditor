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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

/**
 * The outcome of comparing two reports by finding fingerprint.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReportDiff
{
    /**
     * @param list<DiffFinding> $newFindings        present in the current report, absent from the previous one
     * @param list<DiffFinding> $fixedFindings      present in the previous report, absent from the current one
     * @param list<DiffFinding> $persistingFindings present in both reports
     * @param list<DiffFinding> $unverifiedFindings absent from the current report but not fixed: their file was not fully analyzed, or the run left them out as accepted or muted
     */
    public function __construct(
        public array $newFindings,
        public array $fixedFindings,
        public array $persistingFindings,
        public array $unverifiedFindings = [],
    ) {}

    /**
     * @return array{
     *     new: list<array{fingerprint: string, type: string, file: string, title: string, severity: string}>,
     *     fixed: list<array{fingerprint: string, type: string, file: string, title: string, severity: string}>,
     *     unverified: list<array{fingerprint: string, type: string, file: string, title: string, severity: string}>,
     *     persisting: list<array{fingerprint: string, type: string, file: string, title: string, severity: string}>,
     * }
     */
    public function toArray(): array
    {
        return [
            'new' => $this->toArrayList($this->newFindings),
            'fixed' => $this->toArrayList($this->fixedFindings),
            'unverified' => $this->toArrayList($this->unverifiedFindings),
            'persisting' => $this->toArrayList($this->persistingFindings),
        ];
    }

    /**
     * @param list<DiffFinding> $findings
     *
     * @return list<array{fingerprint: string, type: string, file: string, title: string, severity: string}>
     */
    private function toArrayList(array $findings): array
    {
        return array_map(static fn (DiffFinding $diffFinding): array => $diffFinding->toArray(), $findings);
    }
}
