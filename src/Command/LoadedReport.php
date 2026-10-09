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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\UnanalyzedFiles;

/**
 * What a JSON audit report tells a comparison: its findings, the fingerprints
 * of the findings it left out because the baseline accepted them or their type
 * is muted, the files it could not fully analyze, and — when it carries a
 * coverage ledger — the files its attacker analyzed or served from its cache,
 * the files its ledger names at all, and the scan scope of a complete run over
 * the whole history. Only in the files it analyzed, or in a file such a run no
 * longer lists, can the absence of a finding prove anything.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LoadedReport
{
    /** @var array<string, int> */
    private array $unanalyzed;

    /** @var array<string, int>|null */
    private ?array $analyzed;

    /** @var array<string, int> */
    private array $ledger;

    /**
     * @param list<DiffFinding>                                             $findings
     * @param list<string>                                                  $suppressedFingerprints one entry per occurrence the report left out
     * @param list<array{stage: string, file: string, status: string}>|null $coverage               null for a report written before the coverage ledger existed
     * @param list<string>|null                                             $completeRunScanPaths   the `--path` scopes of a complete run over the whole history
     *                                                                                              (no `--since`); null when the report records no scope or ran
     *                                                                                              otherwise
     */
    public function __construct(
        public array $findings,
        public array $suppressedFingerprints = [],
        ?array $coverage = null,
        private ?array $completeRunScanPaths = null,
    ) {
        $this->unanalyzed = array_flip(array_map(EchoedFilePath::normalize(...), UnanalyzedFiles::in($coverage ?? [])));
        $this->analyzed = null === $coverage ? null : array_flip(array_map(EchoedFilePath::normalize(...), AnalyzedFiles::in($coverage)));
        $this->ledger = array_flip(array_map(EchoedFilePath::normalize(...), array_column($coverage ?? [], 'file')));
    }

    /**
     * Whether this report can vouch that a finding absent from it is gone from
     * `$file`: no stage of its run left the file unfinished, and its ledger says
     * the attacker analyzed the file or served it from its cache — or the run
     * was complete, over the whole history, and its ledger never lists the
     * file although its scan scope holds it, so the file is gone. A file the
     * lean pre-scan skipped, or one outside a `--since` or `--path` scope, was
     * never looked at. A report written before the ledger existed vouches for
     * every file it does not name as unanalyzed, as it always did. A finding
     * holds the path the attacker echoed, and so do the reviewer's entries in
     * the ledger, so a leading `./` is dropped on both sides before they are
     * compared.
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
