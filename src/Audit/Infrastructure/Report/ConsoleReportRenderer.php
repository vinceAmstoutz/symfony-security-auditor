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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ConsoleReportRenderer implements ReportRendererInterface
{
    public function __construct(
        private TemplateLoader $templateLoader = new TemplateLoader(),
    ) {}

    #[Override]
    public function format(): string
    {
        return 'console';
    }

    #[Override]
    public function render(AuditReport $auditReport): string
    {
        $cost = $auditReport->cost();

        return strtr($this->templateLoader->load('console.txt'), [
            '{{auditId}}' => $auditReport->auditId(),
            '{{packageName}}' => ReportPackage::NAME,
            '{{packageUrl}}' => ReportPackage::HOMEPAGE_URL,
            '{{projectPath}}' => $auditReport->projectPath(),
            '{{startedAt}}' => $auditReport->startedAt()->format('Y-m-d H:i:s'),
            '{{duration}}' => \sprintf('%.1fs', $auditReport->durationSeconds()),
            '{{filesScanned}}' => $auditReport->filesScanned(),
            '{{tokens}}' => \sprintf('%s in / %s out', number_format($cost->inputTokens()), number_format($cost->outputTokens())),
            '{{primaryModel}}' => '' === $cost->primaryModel() ? 'unknown model' : $cost->primaryModel(),
            '{{riskLevel}}' => $auditReport->riskLevel(),
            '{{riskScore}}' => $auditReport->riskScore(),
            '{{body}}' => $this->body($auditReport),
        ]);
    }

    private function body(AuditReport $auditReport): string
    {
        if (0 === $auditReport->totalVulnerabilities()) {
            return "  ✅  No validated vulnerabilities found.\n";
        }

        $lines = ['  SUMMARY BY SEVERITY'];

        foreach (VulnerabilitySeverity::cases() as $severity) {
            $count = \count($auditReport->vulnerabilitiesBySeverity($severity));
            if ($count > 0) {
                $lines[] = \sprintf('  %-12s %d', $severity->label(), $count);
            }
        }

        $lines[] = '';
        $lines[] = str_repeat('─', 70);
        $lines[] = \sprintf('  VULNERABILITIES (%d total)', $auditReport->totalVulnerabilities());
        $lines[] = str_repeat('─', 70);

        foreach ($auditReport->vulnerabilities() as $vulnerability) {
            $lines[] = $this->vulnerability($vulnerability);
        }

        return implode("\n", $lines);
    }

    private function vulnerability(Vulnerability $vulnerability): string
    {
        return strtr($this->templateLoader->load('vulnerability.txt'), [
            '{{id}}' => $vulnerability->id(),
            '{{severity}}' => $vulnerability->severity()->label(),
            '{{title}}' => $vulnerability->title(),
            '{{owasp}}' => $vulnerability->type()->owaspReference(),
            '{{filePath}}' => $vulnerability->filePath(),
            '{{lineStart}}' => $vulnerability->lineStart(),
            '{{lineEnd}}' => $vulnerability->lineEnd(),
            '{{description}}' => $this->indentChunks($vulnerability->description()),
            '{{attackVector}}' => $this->indentChunks($vulnerability->attackVector()),
            '{{proof}}' => $vulnerability->proof(),
            '{{remediation}}' => $this->indentChunks($vulnerability->remediation()),
            '{{confidence}}' => \sprintf('%.0f', $vulnerability->confidence() * 100),
        ]);
    }

    private function indentChunks(string $text): string
    {
        return implode("\n", array_map(
            static fn (string $chunk): string => \sprintf('    %s', $chunk),
            str_split($text, 65),
        ));
    }
}
