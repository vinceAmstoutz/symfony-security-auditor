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
final readonly class HtmlReportRenderer implements ReportRendererInterface
{
    public function __construct(
        private TemplateLoader $templateLoader = new TemplateLoader(),
    ) {}

    #[Override]
    public function format(): string
    {
        return 'html';
    }

    #[Override]
    public function render(AuditReport $auditReport): string
    {
        $cost = $auditReport->cost();
        $riskLevel = $auditReport->riskLevel();

        return strtr($this->templateLoader->load('report.html'), [
            '{{auditId}}' => $this->escape($auditReport->auditId()),
            '{{packageName}}' => $this->escape(ReportPackage::NAME),
            '{{packageUrl}}' => $this->escape(ReportPackage::HOMEPAGE_URL),
            '{{projectPath}}' => $this->escape($auditReport->projectPath()),
            '{{startedAt}}' => $this->escape($auditReport->startedAt()->format('Y-m-d H:i:s')),
            '{{duration}}' => $this->escape(\sprintf('%ss', number_format($auditReport->durationSeconds(), 1, '.', ''))),
            '{{filesScanned}}' => $auditReport->filesScanned(),
            '{{tokens}}' => $this->escape(\sprintf('%s in / %s out', number_format($cost->inputTokens()), number_format($cost->outputTokens()))),
            '{{primaryModel}}' => $this->escape('' === $cost->primaryModel() ? 'unknown model' : $cost->primaryModel()),
            '{{riskLevel}}' => $this->escape($riskLevel),
            '{{riskLevelClass}}' => $this->escape(strtolower($riskLevel)),
            '{{riskScore}}' => $auditReport->riskScore(),
            '{{summary}}' => $this->summary($auditReport),
            '{{body}}' => $this->body($auditReport),
        ]);
    }

    private function summary(AuditReport $auditReport): string
    {
        if (0 === $auditReport->totalVulnerabilities()) {
            return '<p class="safe">No validated vulnerabilities found.</p>';
        }

        $rows = [];
        foreach (VulnerabilitySeverity::cases() as $severity) {
            $count = \count($auditReport->vulnerabilitiesBySeverity($severity));
            if ($count > 0) {
                $rows[] = \sprintf(
                    '<tr class="severity-%s"><th>%s</th><td>%d</td></tr>',
                    $this->escape($severity->value),
                    $this->escape($severity->label()),
                    $count,
                );
            }
        }

        return \sprintf('<table class="summary"><caption>Summary by severity</caption>%s</table>', implode('', $rows));
    }

    private function body(AuditReport $auditReport): string
    {
        if (0 === $auditReport->totalVulnerabilities()) {
            return '';
        }

        $cards = array_map(
            fn (Vulnerability $vulnerability): string => $this->vulnerability($vulnerability),
            $auditReport->vulnerabilities(),
        );

        return \sprintf(
            '<h2>Vulnerabilities (%d total)</h2>%s',
            $auditReport->totalVulnerabilities(),
            implode('', $cards),
        );
    }

    private function vulnerability(Vulnerability $vulnerability): string
    {
        return strtr($this->templateLoader->load('vulnerability.html'), [
            '{{id}}' => $this->escape($vulnerability->id()),
            '{{severity}}' => $this->escape($vulnerability->severity()->label()),
            '{{severityClass}}' => $this->escape($vulnerability->severity()->value),
            '{{title}}' => $this->escape($vulnerability->title()),
            '{{owasp}}' => $this->escape($vulnerability->type()->owaspReference()),
            '{{cwe}}' => $this->escape($vulnerability->type()->cwe()->label()),
            '{{type}}' => $this->escape($vulnerability->type()->value),
            '{{location}}' => $this->escape(\sprintf(
                '%s:%d-%d',
                $vulnerability->filePath(),
                $vulnerability->lineStart(),
                $vulnerability->lineEnd(),
            )),
            '{{description}}' => $this->escape($vulnerability->description()),
            '{{vulnerableCode}}' => $this->escape($vulnerability->vulnerableCode()),
            '{{attackVector}}' => $this->escape($vulnerability->attackVector()),
            '{{proof}}' => $this->escape($vulnerability->proof()),
            '{{synthesizedPoc}}' => $this->synthesizedPocSection($vulnerability),
            '{{remediation}}' => $this->escape($vulnerability->remediation()),
            '{{confidence}}' => $this->escape(\sprintf('%.0f', $vulnerability->confidence() * 100)),
        ]);
    }

    private function synthesizedPocSection(Vulnerability $vulnerability): string
    {
        $synthesizedPoC = $vulnerability->synthesizedPoC();

        return null === $synthesizedPoC ? '' : \sprintf("<h4>Synthesized PoC</h4>\n  <pre>%s</pre>", $this->escape($synthesizedPoC));
    }

    /**
     * `htmlspecialchars()` neutralizes markup injection (`<`, `>`, `&`,
     * quotes) but a browser still honours the Unicode Bidirectional
     * Algorithm on the escaped text — a bidi override (`U+202A`-`U+202E`,
     * `U+2066`-`U+2069`) in an LLM-sourced field can visually reorder the
     * rendered characters, a Trojan-Source-style spoof of the finding text.
     * Invalid UTF-8 is repaired with `mb_scrub()` first, the same defense the
     * sibling console/Markdown/annotation renderers apply: a `/u` regex aborts
     * (returns `null`) on an invalid subject byte, so without the scrub a
     * single stray byte would defeat the bidi strip entirely.
     */
    private function escape(string $value): string
    {
        $scrubbed = mb_scrub($value, 'UTF-8');
        $withoutBidiOverrides = preg_replace('/[\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', '', $scrubbed) ?? $scrubbed;

        return htmlspecialchars($withoutBidiOverrides, \ENT_QUOTES | \ENT_SUBSTITUTE, 'UTF-8');
    }
}
