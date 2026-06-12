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
        private string $auditId,
        private string $projectPath,
        private DateTimeImmutable $startedAt,
        private DateTimeImmutable $completedAt,
        private int $filesScanned,
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
            $auditContext->auditId(),
            $auditContext->projectPath(),
            $auditContext->startedAt(),
            new DateTimeImmutable(),
            \count($auditContext->projectFiles()),
            $auditContext->coverage(),
            $auditCost,
            ...$auditContext->validatedVulnerabilities(),
        );
    }

    public function auditId(): string
    {
        return $this->auditId;
    }

    public function projectPath(): string
    {
        return $this->projectPath;
    }

    public function startedAt(): DateTimeImmutable
    {
        return $this->startedAt;
    }

    public function completedAt(): DateTimeImmutable
    {
        return $this->completedAt;
    }

    public function filesScanned(): int
    {
        return $this->filesScanned;
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

    public function durationSeconds(): float
    {
        return (float) ($this->completedAt->getTimestamp() - $this->startedAt->getTimestamp());
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
        $score = $this->riskScore();

        return match (true) {
            $score >= 50 => 'CRITICAL',
            $score >= 30 => 'HIGH',
            $score >= 15 => 'MEDIUM',
            $score >= 5 => 'LOW',
            default => 'SAFE',
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
            'audit_id' => $this->auditId,
            'project' => $this->projectPath,
            'started_at' => $this->startedAt->format(DateTimeInterface::ATOM),
            'completed_at' => $this->completedAt->format(DateTimeInterface::ATOM),
            'duration_seconds' => $this->durationSeconds(),
            'files_scanned' => $this->filesScanned,
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
