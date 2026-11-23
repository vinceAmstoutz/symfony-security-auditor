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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

use DateTimeImmutable;
use DateTimeInterface;

final readonly class AuditReport
{
    /** @var list<Vulnerability> */
    private array $vulnerabilities;

    private AuditCost $auditCost;

    /**
     * @param list<array{stage: string, file: string, status: string}> $coverage
     */
    private function __construct(
        private ReportIdentity $reportIdentity,
        private array $coverage,
        ?AuditCost $auditCost,
        private SuppressedFindings $suppressedFindings,
        Vulnerability ...$vulnerabilities,
    ) {
        $this->vulnerabilities = $this->orderedMostSevereFirst(array_values($vulnerabilities));
        $this->auditCost = $auditCost ?? AuditCost::zero('');
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     *
     * @return list<Vulnerability>
     */
    private function orderedMostSevereFirst(array $vulnerabilities): array
    {
        usort(
            $vulnerabilities,
            static fn (Vulnerability $left, Vulnerability $right): int => $right->severity()->score() <=> $left->severity()->score(),
        );

        return $vulnerabilities;
    }

    public static function fromContext(AuditContext $auditContext, ?AuditCost $auditCost = null): self
    {
        return new self(
            new ReportIdentity(
                $auditContext->auditId(),
                $auditContext->projectPath(),
                $auditContext->startedAt(),
                new DateTimeImmutable(),
                \count($auditContext->projectFiles()),
                $auditContext->filesDiscovered(),
                $auditContext->isCostEstimate(),
                $auditContext->diffSinceRef(),
                $auditContext->scanPaths(),
            ),
            $auditContext->coverage(),
            $auditCost,
            new SuppressedFindings($auditContext->baselineAcceptedFindings()),
            ...$auditContext->validatedVulnerabilities(),
        );
    }

    /**
     * Baseline fingerprints spent this run skipping a finding before review,
     * which applying the baseline to the final report must not credit again.
     *
     * @return list<string>
     */
    public function consumedBaselineFingerprints(): array
    {
        return $this->suppressedFindings->baselineFingerprintsAcceptedBeforeReview();
    }

    /**
     * Names each finding the baseline accepted before review after the entry
     * whose credit it spent
     * ({@see SuppressedFindings::withAcceptedBeforeReviewNamedBy()}).
     *
     * @internal not part of the BC promise, see docs/versioning.md
     *
     * @param array<string, list<string>> $entryFingerprintsByBaselineFingerprint
     */
    public function withFindingsAcceptedBeforeReviewNamedBy(array $entryFingerprintsByBaselineFingerprint): self
    {
        return new self(
            $this->reportIdentity,
            $this->coverage,
            $this->auditCost,
            $this->suppressedFindings->withAcceptedBeforeReviewNamedBy($entryFingerprintsByBaselineFingerprint),
            ...$this->vulnerabilities,
        );
    }

    public function auditId(): string
    {
        return $this->reportIdentity->auditId;
    }

    public function projectPath(): string
    {
        return $this->reportIdentity->projectPath;
    }

    public function startedAt(): DateTimeImmutable
    {
        return $this->reportIdentity->startedAt;
    }

    public function completedAt(): DateTimeImmutable
    {
        return $this->reportIdentity->completedAt;
    }

    public function filesScanned(): int
    {
        return $this->reportIdentity->filesScanned;
    }

    /**
     * How many files the scan found, before a `--since` diff narrowed them.
     * Zero means nothing was examined, so the report carries no verdict.
     */
    public function filesDiscovered(): int
    {
        return $this->reportIdentity->filesDiscovered;
    }

    public function cost(): AuditCost
    {
        return $this->auditCost;
    }

    /**
     * @return list<array{stage: string, file: string, status: string}>
     */
    public function coverage(): array
    {
        return $this->coverage;
    }

    /**
     * Files some stage set out to analyze and never finished
     * ({@see UnanalyzedFiles}). A report listing one cannot vouch for the
     * absence of vulnerabilities.
     *
     * @return list<string>
     */
    public function unanalyzedFiles(): array
    {
        return UnanalyzedFiles::in($this->coverage);
    }

    /**
     * Whether no stage left a file in scope unfinished and the report is no
     * cost estimate. A run that had no file to analyze, or records no
     * coverage, is complete.
     */
    public function isComplete(): bool
    {
        return [] === $this->unanalyzedFiles() && !$this->estimatesFilesItNeverAnalyzed();
    }

    /**
     * Whether the run analyzed none of the files it had to and holds no
     * finding: a SAFE there would vouch for code nobody read. A run holding a
     * finding is partial instead. A scan that found no file is
     * {@see self::foundNoFile()}, which this does not answer.
     */
    public function hasNoVerdict(): bool
    {
        return !$this->isComplete() && [] === $this->vulnerabilities && [] === AnalyzedFiles::in($this->coverage);
    }

    /**
     * Whether the scan found no file at all, before a `--since` diff narrowed
     * them: nothing was examined.
     */
    public function foundNoFile(): bool
    {
        return 0 === $this->reportIdentity->filesDiscovered;
    }

    /**
     * Whether the report can vouch for nothing: the scan found no file, or the
     * run reached no verdict ({@see self::hasNoVerdict()}). Neither may be
     * presented as a clean result.
     */
    public function isWithoutVerdict(): bool
    {
        return $this->foundNoFile() || $this->hasNoVerdict();
    }

    private function estimatesFilesItNeverAnalyzed(): bool
    {
        return $this->reportIdentity->costEstimate && $this->reportIdentity->filesScanned > 0;
    }

    /** @return list<Vulnerability> */
    public function vulnerabilities(): array
    {
        return $this->vulnerabilities;
    }

    /**
     * The de-duplicated fingerprints of every finding: what a baseline file
     * holds.
     *
     * @return list<string>
     */
    public function fingerprints(): array
    {
        return array_values(array_unique(array_map(
            static fn (Vulnerability $vulnerability): string => $vulnerability->fingerprint(),
            $this->vulnerabilities,
        )));
    }

    /**
     * Removes at most as many findings per fingerprint as `$fingerprints` holds
     * it, so one accepted occurrence never suppresses every finding sharing its
     * fingerprint.
     *
     * @param list<string> $fingerprints
     */
    public function withoutFingerprints(array $fingerprints): self
    {
        $remainingByFingerprint = array_count_values($fingerprints);

        $kept = [];
        $removed = [];
        foreach ($this->vulnerabilities as $vulnerability) {
            $creditedFingerprint = $this->creditedFingerprint($vulnerability, $remainingByFingerprint);
            if (null !== $creditedFingerprint) {
                --$remainingByFingerprint[$creditedFingerprint];
                $removed[] = new SuppressedFinding($vulnerability->fingerprint(), $creditedFingerprint);

                continue;
            }

            $kept[] = $vulnerability;
        }

        return new self(
            $this->reportIdentity,
            $this->coverage,
            $this->auditCost,
            $this->suppressedFindings->withRemovedFindings($removed),
            ...$kept,
        );
    }

    /**
     * @param array<string, int> $remainingByFingerprint
     */
    private function creditedFingerprint(Vulnerability $vulnerability, array $remainingByFingerprint): ?string
    {
        foreach ($vulnerability->fingerprintCandidates() as $fingerprintCandidate) {
            if (\array_key_exists($fingerprintCandidate, $remainingByFingerprint) && $remainingByFingerprint[$fingerprintCandidate] > 0) {
                return $fingerprintCandidate;
            }
        }

        return null;
    }

    /**
     * Keeps the findings whose type passes the filters: a non-empty
     * `$includedTypes` is an allowlist and `$excludedTypes` always wins over it.
     *
     * @param list<VulnerabilityType> $includedTypes
     * @param list<VulnerabilityType> $excludedTypes
     */
    public function filteredByTypes(array $includedTypes, array $excludedTypes): self
    {
        $kept = array_filter(
            $this->vulnerabilities,
            static fn (Vulnerability $vulnerability): bool => ([] === $includedTypes || $vulnerability->matchesAnyType($includedTypes))
                && !$vulnerability->matchesAnyType($excludedTypes),
        );

        return new self(
            $this->reportIdentity,
            $this->coverage,
            $this->auditCost,
            $this->suppressedFindings->withRemoved(array_diff_key($this->vulnerabilities, $kept)),
            ...$kept,
        );
    }

    public function durationSeconds(): float
    {
        return $this->reportIdentity->durationSeconds();
    }

    public function totalVulnerabilities(): int
    {
        return \count($this->vulnerabilities);
    }

    /** @return list<Vulnerability> */
    public function vulnerabilitiesBySeverity(VulnerabilitySeverity $vulnerabilitySeverity): array
    {
        return array_values(array_filter(
            $this->vulnerabilities,
            static fn (Vulnerability $vulnerability): bool => $vulnerability->severity() === $vulnerabilitySeverity,
        ));
    }

    /** @return list<Vulnerability> */
    public function vulnerabilitiesByType(VulnerabilityType $vulnerabilityType): array
    {
        return array_values(array_filter(
            $this->vulnerabilities,
            static fn (Vulnerability $vulnerability): bool => $vulnerability->type() === $vulnerabilityType,
        ));
    }

    public function riskScore(): int
    {
        return array_sum(
            array_map(
                static fn (Vulnerability $vulnerability): int => $vulnerability->severity()->score(),
                $this->vulnerabilities,
            ),
        );
    }

    /**
     * The bounded counterpart of {@see riskScore()}: 100 for a clean report,
     * each finding deducting its severity's `score()`, floored at 0.
     */
    public function normalizedScore(): int
    {
        return max(0, 100 - $this->riskScore());
    }

    public function grade(): SecurityGrade
    {
        return SecurityGrade::fromNormalizedScore($this->normalizedScore());
    }

    public function riskLevel(): string
    {
        return strtoupper($this->riskLevelEnum()->value);
    }

    public function riskLevelEnum(): RiskLevel
    {
        $score = $this->riskScore();

        return match (true) {
            $score >= 50 => RiskLevel::Critical,
            $score >= 30 => RiskLevel::High,
            $score >= 15 => RiskLevel::Medium,
            $score >= 5 => RiskLevel::Low,
            default => RiskLevel::Safe,
        };
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $bySeverity = [];
        foreach (VulnerabilitySeverity::cases() as $severity) {
            $bySeverity[$severity->value] = \count($this->vulnerabilitiesBySeverity($severity));
        }

        return [
            'audit_id' => $this->reportIdentity->auditId,
            'project' => $this->reportIdentity->projectPath,
            'started_at' => $this->reportIdentity->startedAt->format(DateTimeInterface::ATOM),
            'completed_at' => $this->reportIdentity->completedAt->format(DateTimeInterface::ATOM),
            'duration_seconds' => $this->durationSeconds(),
            'files_scanned' => $this->reportIdentity->filesScanned,
            'files_discovered' => $this->reportIdentity->filesDiscovered,
            'complete' => $this->isComplete(),
            'risk_score' => $this->riskScore(),
            'risk_level' => $this->riskLevel(),
            'score' => $this->normalizedScore(),
            'grade' => $this->grade()->value,
            'total_vulnerabilities' => $this->totalVulnerabilities(),
            'by_severity' => $bySeverity,
            'vulnerabilities' => array_map(
                static fn (Vulnerability $vulnerability): array => $vulnerability->toArray(),
                $this->vulnerabilities,
            ),
            'cost' => $this->auditCost->toArray(),
            'scope' => [
                'since' => $this->reportIdentity->diffSinceRef,
                'paths' => $this->reportIdentity->scanPaths,
            ],
            'coverage' => $this->coverage,
            'suppressed_fingerprints' => $this->suppressedFindings->fingerprints(),
            'suppressed_baseline_fingerprints' => $this->suppressedFindings->baselineFingerprints(),
        ];
    }
}
