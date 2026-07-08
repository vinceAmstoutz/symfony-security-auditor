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

use function Symfony\Component\String\u;

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
            '{{duration}}' => \sprintf('%ss', number_format($auditReport->durationSeconds(), 1, '.', '')),
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
            '{{title}}' => $this->sanitizeSingleLineField($vulnerability->title()),
            '{{owasp}}' => $vulnerability->type()->owaspReference(),
            '{{cwe}}' => $vulnerability->type()->cwe()->label(),
            '{{filePath}}' => $this->sanitizeSingleLineField($vulnerability->filePath()),
            '{{lineStart}}' => $vulnerability->lineStart(),
            '{{lineEnd}}' => $vulnerability->lineEnd(),
            '{{description}}' => $this->indentChunks($vulnerability->description()),
            '{{attackVector}}' => $this->indentChunks($vulnerability->attackVector()),
            '{{proof}}' => $this->indentLines($vulnerability->proof()),
            '{{remediation}}' => $this->indentChunks($vulnerability->remediation()),
            '{{confidence}}' => \sprintf('%.0f', $vulnerability->confidence() * 100),
        ]);
    }

    private function indentChunks(string $text): string
    {
        return implode("\n", array_map(
            static fn (string $chunk): string => \sprintf('    %s', $chunk),
            explode("\n", u($this->sanitizeControlCharacters(mb_scrub($text, 'UTF-8')))->wordwrap(65, "\n", true)->toString()),
        ));
    }

    /**
     * Unlike {@see self::indentChunks()}, this does not word-wrap: `proof` is
     * often a literal command or request that would be corrupted by
     * mid-line wrapping, so every existing line is simply prefixed as-is.
     */
    private function indentLines(string $text): string
    {
        return implode("\n", array_map(
            static fn (string $line): string => \sprintf('    %s', $line),
            explode("\n", $this->sanitizeControlCharacters(mb_scrub($text, 'UTF-8'))),
        ));
    }

    /**
     * `ReportWriter` deliberately renders console output with `OUTPUT_RAW` so
     * a finding's own `<tag>`-lookalike text isn't misread as Symfony Console
     * markup — but that only bypasses Symfony's formatter, it does not strip
     * raw control bytes already in the string. An LLM-sourced field quoting
     * attacker-crafted project content verbatim could otherwise carry a real
     * ESC byte (ANSI escape sequences) or carriage return, letting a crafted
     * finding erase or overwrite adjacent terminal output — e.g. hiding a
     * CRITICAL finding behind a forged "all clear" line.
     */
    private function sanitizeControlCharacters(string $text): string
    {
        return preg_replace('/[\x00-\x08\x0B-\x1F\x7F]/', '', $text) ?? $text;
    }

    /**
     * `title`/`filePath` render on a single template line, unlike
     * `description`/`attackVector`/`proof`/`remediation`, which are
     * legitimately multi-line and rendered inside their own indented block —
     * an embedded newline here would let a crafted finding forge a fake
     * `[ID] SEVERITY` finding block as unguarded top-level output.
     */
    private function sanitizeSingleLineField(string $text): string
    {
        return $this->sanitizeControlCharacters(str_replace(["\r\n", "\n", "\r"], ' ', mb_scrub($text, 'UTF-8')));
    }
}
