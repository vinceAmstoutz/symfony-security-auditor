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
 * A heuristic CVSS v4.0 base-metric estimate for a finding.
 *
 * This is an ESTIMATE, not a hand-scored vector: the base score is the
 * representative value of the reviewer-assigned severity's CVSS band, and the
 * exploitability/impact metrics are derived from the vulnerability type's
 * category and that severity. It gives dashboards and Code Scanning a
 * machine-comparable number and a standards-shaped vector without claiming
 * analyst-grade precision — a human triager should refine it before it drives
 * an SLA.
 */
final readonly class CvssEstimate
{
    public const string VERSION = '4.0';

    private function __construct(
        private string $vector,
        private float $baseScore,
    ) {}

    public static function for(VulnerabilityType $vulnerabilityType, VulnerabilitySeverity $vulnerabilitySeverity): self
    {
        [$vulnConfidentiality, $vulnIntegrity, $vulnAvailability] = self::impactMetrics($vulnerabilitySeverity);
        $privilegesRequired = self::privilegesRequired($vulnerabilityType);

        $vector = \sprintf(
            'CVSS:4.0/AV:N/AC:L/AT:N/PR:%s/UI:N/VC:%s/VI:%s/VA:%s/SC:N/SI:N/SA:N',
            $privilegesRequired,
            $vulnConfidentiality,
            $vulnIntegrity,
            $vulnAvailability,
        );

        return new self($vector, self::baseScoreFor($vulnerabilitySeverity));
    }

    public function vector(): string
    {
        return $this->vector;
    }

    public function baseScore(): float
    {
        return $this->baseScore;
    }

    /**
     * @return array{version: string, vector: string, base_score: float}
     */
    public function toArray(): array
    {
        return [
            'version' => self::VERSION,
            'vector' => $this->vector,
            'base_score' => $this->baseScore,
        ];
    }

    /**
     * Representative base score for the severity's CVSS v4.0 qualitative band
     * (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9, None 0.0).
     */
    private static function baseScoreFor(VulnerabilitySeverity $vulnerabilitySeverity): float
    {
        return match ($vulnerabilitySeverity) {
            VulnerabilitySeverity::CRITICAL => 9.3,
            VulnerabilitySeverity::HIGH => 8.1,
            VulnerabilitySeverity::MEDIUM => 5.8,
            VulnerabilitySeverity::LOW => 3.1,
            VulnerabilitySeverity::INFO => 0.0,
        };
    }

    /**
     * @return array{string, string, string} VC, VI, VA metric values
     */
    private static function impactMetrics(VulnerabilitySeverity $vulnerabilitySeverity): array
    {
        return match ($vulnerabilitySeverity) {
            VulnerabilitySeverity::CRITICAL => ['H', 'H', 'H'],
            VulnerabilitySeverity::HIGH => ['H', 'H', 'N'],
            VulnerabilitySeverity::MEDIUM => ['L', 'L', 'N'],
            VulnerabilitySeverity::LOW => ['L', 'N', 'N'],
            VulnerabilitySeverity::INFO => ['N', 'N', 'N'],
        };
    }

    /**
     * Access-control, logic, and Symfony-specific flaws typically require an
     * authenticated session to reach (PR:L); injection, data-exposure, and
     * cryptographic weaknesses are commonly reachable unauthenticated (PR:N).
     */
    private static function privilegesRequired(VulnerabilityType $vulnerabilityType): string
    {
        return match ($vulnerabilityType->category()) {
            'Broken Access Control', 'Logic Flaw', 'Symfony-Specific' => 'L',
            default => 'N',
        };
    }
}
