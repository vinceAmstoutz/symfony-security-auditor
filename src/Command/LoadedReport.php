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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EchoedFilePath;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScanPathFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AnalyzedFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ScanSkippedFiles;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\UnanalyzedFiles;

/**
 * What a JSON audit report tells a comparison. The absence of a finding proves
 * something only in a file the run analyzed, or in a file a complete run over
 * the whole history no longer lists. A file the scan left out
 * ({@see ScanSkippedFiles}) does not count as listed.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class LoadedReport
{
    /** @var array<string, int> */
    private array $unanalyzed;

    /** @var array<string, int>|null */
    private ?array $analyzed;

    /** @var array<string, int> */
    private array $ledger;

    /** @var list<string> one entry per occurrence the report left out, under the fingerprint a report lists the finding under */
    public array $suppressedFingerprints;

    /** @var list<string> the baseline fingerprint that left out each of `$suppressedFingerprints`, in the same order */
    public array $suppressedBaselineFingerprints;

    /**
     * @param list<DiffFinding>                                             $findings
     * @param list<array{stage: string, file: string, status: string}>|null $coverage             null for a report without a coverage ledger
     * @param list<string>|null                                             $completeRunScanPaths the `--path` scopes of a complete run without `--since`, else null
     * @param string|null                                                   $projectPath          the folder the run audited, which an absolute path is read against; null for a report that names each finding as the model did
     */
    public function __construct(
        public array $findings,
        SuppressedFingerprintLists $suppressedFingerprintLists,
        ?array $coverage = null,
        private ?array $completeRunScanPaths = null,
        public ?string $projectPath = null,
    ) {
        $this->suppressedFingerprints = $suppressedFingerprintLists->listed;
        $this->suppressedBaselineFingerprints = $suppressedFingerprintLists->baseline;
        $this->unanalyzed = array_flip(array_map(EchoedFilePath::normalize(...), UnanalyzedFiles::in($coverage ?? [])));
        $this->analyzed = null === $coverage ? null : array_flip(array_map(EchoedFilePath::normalize(...), AnalyzedFiles::in($coverage)));
        $this->ledger = array_flip(array_map(EchoedFilePath::normalize(...), array_column(ScanSkippedFiles::without($coverage ?? []), 'file')));
    }

    /**
     * Whether a finding absent from this report is gone from `$file`: no stage
     * left the file unfinished and the attacker analyzed it or served it from
     * its cache, or a complete run over the whole history no longer lists it
     * within its scope. A report without a ledger vouches for every file it
     * does not name as unanalyzed. A leading `./` is ignored on both sides.
     */
    public function vouchesForAbsenceIn(string $file): bool
    {
        $normalized = EchoedFilePath::normalize($file);

        return !\array_key_exists($normalized, $this->unanalyzed)
            && (null === $this->analyzed || \array_key_exists($normalized, $this->analyzed) || $this->sawTheFileGone($normalized));
    }

    private function sawTheFileGone(string $file): bool
    {
        return null !== $this->completeRunScanPaths
            && !\array_key_exists($file, $this->ledger)
            && ScanPathFilter::includes($file, $this->completeRunScanPaths);
    }
}
