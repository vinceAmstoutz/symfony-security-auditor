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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ExecutiveSummary;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;

use function Symfony\Component\String\u;

/**
 * Renders the stakeholder-facing view of a report: risk level, what it means
 * for the business, and the severity / type / hotspot distributions — without
 * the per-finding technical detail the `console` format carries.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ExecutiveSummaryReportRenderer implements ReportRendererInterface
{
    private const int HOTSPOT_LIMIT = 5;

    private const int LABEL_COLUMN_WIDTH = 48;

    private const int PROSE_WIDTH = 66;

    public function __construct(
        private TemplateLoader $templateLoader = new TemplateLoader(),
    ) {}

    #[Override]
    public function format(): string
    {
        return 'executive';
    }

    #[Override]
    public function render(AuditReport $auditReport): string
    {
        $executiveSummary = ExecutiveSummary::of($auditReport);

        return strtr($this->templateLoader->load('executive.txt'), [
            '{{projectPath}}' => $this->sanitize($auditReport->projectPath()),
            '{{startedAt}}' => $auditReport->startedAt()->format('Y-m-d H:i:s'),
            '{{filesScanned}}' => $auditReport->filesScanned(),
            '{{duration}}' => \sprintf('%ss', number_format($auditReport->durationSeconds(), 1, '.', '')),
            '{{auditId}}' => $auditReport->auditId(),
            '{{riskLevel}}' => $auditReport->riskLevel(),
            '{{riskScore}}' => $executiveSummary->riskScore,
            '{{businessImpact}}' => $this->wrapped($this->businessImpact($executiveSummary->riskLevel)),
            '{{body}}' => $this->body($executiveSummary),
        ]);
    }

    private function businessImpact(RiskLevel $riskLevel): string
    {
        return match ($riskLevel) {
            RiskLevel::Critical => 'Immediate action required: findings at this level let an attacker read or alter data they should never reach, or take over a privileged account.',
            RiskLevel::High => 'Action required this sprint: findings at this level are exploitable by a motivated attacker and put user data or business logic at risk.',
            RiskLevel::Medium => 'Plan remediation: no single finding is decisive, but together they weaken defence in depth and shorten the path to a breach.',
            RiskLevel::Low => 'Low business exposure: fold the fixes into routine maintenance.',
            RiskLevel::Safe => 'No validated findings: this audit identified no business exposure in the scanned surface.',
        };
    }

    private function wrapped(string $prose): string
    {
        return u($prose)->wordwrap(self::PROSE_WIDTH, "\n  ")->toString();
    }

    private function body(ExecutiveSummary $executiveSummary): string
    {
        if (0 === $executiveSummary->totalFindings) {
            return "  No validated vulnerabilities found.\n";
        }

        return implode("\n", [
            \sprintf('  %d validated finding(s) across %d file(s).', $executiveSummary->totalFindings, $executiveSummary->affectedFileCount()),
            '',
            '  BY SEVERITY',
            $this->severityLines($executiveSummary),
            '',
            '  BY TYPE',
            $this->countLines($executiveSummary->typeCounts),
            '',
            \sprintf('  TOP AFFECTED FILES (of %d)', $executiveSummary->affectedFileCount()),
            $this->countLines($executiveSummary->topAffectedFiles(self::HOTSPOT_LIMIT)),
            '',
        ]);
    }

    private function severityLines(ExecutiveSummary $executiveSummary): string
    {
        $labelled = [];
        foreach ($executiveSummary->severityCounts as $severity => $count) {
            $labelled[VulnerabilitySeverity::from($severity)->label()] = $count;
        }

        return $this->countLines($labelled);
    }

    /**
     * @param array<string, int> $counts
     */
    private function countLines(array $counts): string
    {
        $lines = [];
        foreach ($counts as $label => $count) {
            $lines[] = \sprintf('  %s %3d', mb_str_pad($this->sanitize($label), self::LABEL_COLUMN_WIDTH), $count);
        }

        return implode("\n", $lines);
    }

    private function sanitize(string $text): string
    {
        return TerminalTextSanitizer::collapseToSingleLine(mb_scrub($text, 'UTF-8'));
    }
}
