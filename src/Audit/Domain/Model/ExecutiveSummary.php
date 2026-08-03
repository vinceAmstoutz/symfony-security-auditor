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

/**
 * The stakeholder-facing view of an {@see AuditReport}: risk level plus the
 * three distributions a reader needs to size the exposure — by severity, by
 * vulnerability type, and by affected file — with no per-finding detail.
 */
final readonly class ExecutiveSummary
{
    /**
     * @param array<string, int> $severityCounts     severity value => finding count, most severe first, present severities only
     * @param array<string, int> $typeCounts         vulnerability type value => finding count, most frequent first
     * @param array<string, int> $affectedFileCounts file path => finding count, most affected first
     */
    private function __construct(
        public RiskLevel $riskLevel,
        public int $riskScore,
        public int $normalizedScore,
        public SecurityGrade $grade,
        public int $totalFindings,
        public array $severityCounts,
        public array $typeCounts,
        public array $affectedFileCounts,
    ) {}

    public static function of(AuditReport $auditReport): self
    {
        return new self(
            $auditReport->riskLevelEnum(),
            $auditReport->riskScore(),
            $auditReport->normalizedScore(),
            $auditReport->grade(),
            $auditReport->totalVulnerabilities(),
            self::severityCounts($auditReport),
            self::mostFrequentFirst(self::typeCounts($auditReport)),
            self::mostFrequentFirst(self::fileCounts($auditReport)),
        );
    }

    public function affectedFileCount(): int
    {
        return \count($this->affectedFileCounts);
    }

    /**
     * @return array<string, int>
     */
    public function topAffectedFiles(int $limit): array
    {
        return \array_slice($this->affectedFileCounts, 0, max(0, $limit), true);
    }

    /**
     * @return array<string, int>
     */
    private static function severityCounts(AuditReport $auditReport): array
    {
        $counts = [];
        foreach (VulnerabilitySeverity::cases() as $severity) {
            $count = \count($auditReport->vulnerabilitiesBySeverity($severity));
            if ($count > 0) {
                $counts[$severity->value] = $count;
            }
        }

        return $counts;
    }

    /**
     * @return array<string, int>
     */
    private static function typeCounts(AuditReport $auditReport): array
    {
        $counts = [];
        foreach ($auditReport->vulnerabilities() as $vulnerability) {
            $type = $vulnerability->type()->value;
            $counts[$type] = ($counts[$type] ?? 0) + 1;
        }

        return $counts;
    }

    /**
     * @return array<string, int>
     */
    private static function fileCounts(AuditReport $auditReport): array
    {
        $counts = [];
        foreach ($auditReport->vulnerabilities() as $vulnerability) {
            $filePath = $vulnerability->filePath();
            $counts[$filePath] = ($counts[$filePath] ?? 0) + 1;
        }

        return $counts;
    }

    /**
     * @param array<string, int> $counts
     *
     * @return array<string, int>
     */
    private static function mostFrequentFirst(array $counts): array
    {
        $labels = array_keys($counts);
        usort(
            $labels,
            static function (string $left, string $right) use ($counts): int {
                $byDescendingCount = $counts[$right] <=> $counts[$left];

                return 0 !== $byDescendingCount ? $byDescendingCount : strcmp($left, $right);
            },
        );

        $ordered = [];
        foreach ($labels as $label) {
            $ordered[$label] = $counts[$label];
        }

        return $ordered;
    }
}
