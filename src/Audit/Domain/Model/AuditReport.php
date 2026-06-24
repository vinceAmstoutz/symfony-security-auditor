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
            ),
            $auditContext->coverage(),
            $auditCost,
            ...$auditContext->validatedVulnerabilities(),
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
     * Copy of the report with every finding whose fingerprint appears in
     * `$fingerprints` removed — used to suppress baselined (accepted) findings
     * before rendering and exit-code resolution.
     *
     * @param list<string> $fingerprints
     */
    public function withoutFingerprints(array $fingerprints): self
    {
        $kept = array_filter(
            $this->vulnerabilities,
            static fn (Vulnerability $vulnerability): bool => !\in_array($vulnerability->fingerprint(), $fingerprints, true),
        );

        return new self(
            $this->reportIdentity,
            $this->coverage,
            $this->auditCost,
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
            ...$kept,
        );
    }

    public function durationSeconds(): float
    {
        return (float) ($this->reportIdentity->completedAt->getTimestamp() - $this->reportIdentity->startedAt->getTimestamp());
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
            'risk_score' => $this->riskScore(),
            'risk_level' => $this->riskLevel(),
            'total_vulnerabilities' => $this->totalVulnerabilities(),
            'by_severity' => $bySeverity,
            'vulnerabilities' => array_map(
                static fn (Vulnerability $vulnerability): array => $vulnerability->toArray(),
                $this->vulnerabilities,
            ),
            'cost' => $this->auditCost->toArray(),
            'coverage' => $this->coverage,
        ];
    }
}
