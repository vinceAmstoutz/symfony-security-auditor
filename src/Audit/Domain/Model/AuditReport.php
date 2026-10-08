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
            new SuppressedFindings($auditContext->consumedBaselineFingerprints()),
            ...$auditContext->validatedVulnerabilities(),
        );
    }

    /**
     * Baseline fingerprints already spent skipping a finding before the
     * reviewer ever saw it this run — lets `BaselineProcessor` avoid granting
     * the same accepted occurrence a second, unspent credit when it applies
     * the baseline again against the final report.
     *
     * @return list<string>
     */
    public function consumedBaselineFingerprints(): array
    {
        return $this->suppressedFindings->acceptedBeforeReview;
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
     * Files some stage set out to analyze and never finished — see
     * {@see UnanalyzedFiles}. A finding can hide in any of them, so a report
     * listing one cannot vouch for the absence of vulnerabilities.
     *
     * @return list<string>
     */
    public function unanalyzedFiles(): array
    {
        return UnanalyzedFiles::in($this->coverage);
    }

    /**
     * Whether every file in scope was analyzed: no stage left one unfinished —
     * a run stopped before its first LLM call records its files as aborted —
     * and the report is not a cost estimate of files it never analyzed. A
     * `--since` run whose diff left no file to analyze has nothing left
     * unfinished, and neither has a host pipeline that records no coverage.
     */
    public function isComplete(): bool
    {
        return [] === $this->unanalyzedFiles() && !$this->estimatesFilesItNeverAnalyzed();
    }

    /**
     * Whether the run reached no verdict: its scan found no file at all, or it
     * analyzed none of the files it had to — every attacker call failed or was
     * cut short, or none was made — and holds no finding. A SAFE there would
     * vouch for code nobody read. A run that holds a finding is a partial run
     * even when it analyzed no file in full: a response cut short keeps the
     * findings it recorded, while its chunk is recorded as errored.
     */
    public function hasNoVerdict(): bool
    {
        return 0 === $this->reportIdentity->filesDiscovered || $this->analyzedNoFileAndFoundNothing();
    }

    private function analyzedNoFileAndFoundNothing(): bool
    {
        return !$this->isComplete() && [] === $this->vulnerabilities && [] === AnalyzedFiles::in($this->coverage);
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
     * Stable fingerprints of every finding in the report, de-duplicated — the
     * payload written to a baseline file.
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
     * Copy of the report with findings removed by fingerprint, consuming at
     * most as many findings per fingerprint as `$fingerprints` contains that
     * value — a plain membership test would let one accepted occurrence of a
     * shared fingerprint suppress every current finding sharing it, including
     * ones that were never actually reviewed.
     *
     * @param list<string> $fingerprints
     */
    public function withoutFingerprints(array $fingerprints): self
    {
        $remainingByFingerprint = array_count_values($fingerprints);

        $kept = [];
        $removed = [];
        foreach ($this->vulnerabilities as $vulnerability) {
            $fingerprint = $vulnerability->fingerprint();
            if (\array_key_exists($fingerprint, $remainingByFingerprint) && $remainingByFingerprint[$fingerprint] > 0) {
                --$remainingByFingerprint[$fingerprint];
                $removed[] = $vulnerability;

                continue;
            }

            $kept[] = $vulnerability;
        }

        return new self(
            $this->reportIdentity,
            $this->coverage,
            $this->auditCost,
            $this->suppressedFindings->withRemoved($removed),
            ...$kept,
        );
    }

    /**
     * Copy of the report keeping only findings whose type passes the configured
     * filters: when `$includedTypes` is non-empty it acts as an allowlist, and
     * `$excludedTypes` always wins over it. Applied before rendering and
     * exit-code resolution so muted types neither appear nor fail CI.
     *
     * @param list<VulnerabilityType> $includedTypes
     * @param list<VulnerabilityType> $excludedTypes
     */
    public function filteredByTypes(array $includedTypes, array $excludedTypes): self
    {
        $kept = array_filter(
            $this->vulnerabilities,
            static fn (Vulnerability $vulnerability): bool => ([] === $includedTypes || \in_array($vulnerability->type(), $includedTypes, true))
                && !\in_array($vulnerability->type(), $excludedTypes, true),
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
     * each finding deducting its severity's `score()` weight, floored at 0.
     * Reusing that one weight table keeps the two scales from drifting apart.
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
        ];
    }
}
