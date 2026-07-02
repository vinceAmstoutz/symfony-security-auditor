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

use Composer\InstalledVersions;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class ReportRenderer
{
    public const string PACKAGE_NAME = 'vinceamstoutz/symfony-security-auditor';

    public const string HOMEPAGE_URL = 'https://github.com/vinceamstoutz/symfony-security-auditor';

    public const string UNKNOWN_VERSION = 'unknown';

    private const string TEMPLATE_DIRECTORY_NAME = 'Template';

    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    public function renderConsole(AuditReport $auditReport): string
    {
        $cost = $auditReport->cost();

        return strtr($this->loadTemplate('console.txt'), [
            '{{auditId}}' => $auditReport->auditId(),
            '{{packageName}}' => self::PACKAGE_NAME,
            '{{packageUrl}}' => self::HOMEPAGE_URL,
            '{{projectPath}}' => $auditReport->projectPath(),
            '{{startedAt}}' => $auditReport->startedAt()->format('Y-m-d H:i:s'),
            '{{duration}}' => \sprintf('%.1fs', $auditReport->durationSeconds()),
            '{{filesScanned}}' => $auditReport->filesScanned(),
            '{{tokens}}' => \sprintf('%s in / %s out', number_format($cost->inputTokens()), number_format($cost->outputTokens())),
            '{{primaryModel}}' => '' === $cost->primaryModel() ? 'unknown model' : $cost->primaryModel(),
            '{{riskLevel}}' => $auditReport->riskLevel(),
            '{{riskScore}}' => $auditReport->riskScore(),
            '{{body}}' => $this->renderBody($auditReport),
        ]);
    }

    public function renderJson(AuditReport $auditReport): string
    {
        return json_encode($auditReport->toArray(), \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR);
    }

    public function renderHtml(AuditReport $auditReport): string
    {
        $cost = $auditReport->cost();
        $riskLevel = $auditReport->riskLevel();

        return strtr($this->loadTemplate('report.html'), [
            '{{auditId}}' => $this->escape($auditReport->auditId()),
            '{{packageName}}' => $this->escape(self::PACKAGE_NAME),
            '{{packageUrl}}' => $this->escape(self::HOMEPAGE_URL),
            '{{projectPath}}' => $this->escape($auditReport->projectPath()),
            '{{startedAt}}' => $this->escape($auditReport->startedAt()->format('Y-m-d H:i:s')),
            '{{duration}}' => $this->escape(\sprintf('%.1fs', $auditReport->durationSeconds())),
            '{{filesScanned}}' => $auditReport->filesScanned(),
            '{{tokens}}' => $this->escape(\sprintf('%s in / %s out', number_format($cost->inputTokens()), number_format($cost->outputTokens()))),
            '{{primaryModel}}' => $this->escape('' === $cost->primaryModel() ? 'unknown model' : $cost->primaryModel()),
            '{{riskLevel}}' => $this->escape($riskLevel),
            '{{riskLevelClass}}' => $this->escape(strtolower($riskLevel)),
            '{{riskScore}}' => $auditReport->riskScore(),
            '{{summary}}' => $this->htmlSummary($auditReport),
            '{{body}}' => $this->htmlBody($auditReport),
        ]);
    }

    public function renderSarif(AuditReport $auditReport): string
    {
        $vulnerabilities = $auditReport->vulnerabilities();

        $results = [];
        $types = [];

        foreach ($vulnerabilities as $vulnerability) {
            $type = $vulnerability->type();
            $types[$type->owaspReference()] = $type;

            $results[] = [
                'ruleId' => $type->owaspReference(),
                'level' => $this->sarifLevel($vulnerability->severity()),
                'message' => ['text' => $vulnerability->title()],
                'partialFingerprints' => ['symfonySecurityAuditor/v1' => $vulnerability->fingerprint()],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => ['uri' => $vulnerability->filePath()],
                            'region' => [
                                'startLine' => $vulnerability->lineStart(),
                                'endLine' => $vulnerability->lineEnd(),
                            ],
                        ],
                    ],
                ],
            ];
        }

        $rules = array_values(array_map(
            static fn (VulnerabilityType $vulnerabilityType): array => [
                'id' => $vulnerabilityType->owaspReference(),
                'name' => $vulnerabilityType->value,
                'shortDescription' => ['text' => $vulnerabilityType->category()],
                'helpUri' => $vulnerabilityType->owaspReferenceUrl(),
            ],
            $types,
        ));

        $cost = $auditReport->cost();
        $sarif = [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'Symfony Security Auditor',
                            'version' => $this->packageVersion(),
                            'informationUri' => self::HOMEPAGE_URL,
                            'rules' => $rules,
                        ],
                    ],
                    'results' => $results,
                    'properties' => [
                        'input_tokens' => $cost->inputTokens(),
                        'output_tokens' => $cost->outputTokens(),
                        'total_tokens' => $cost->totalTokens(),
                        'estimated_cost_usd' => $cost->estimatedCostUsd(),
                        'primary_model' => $cost->primaryModel(),
                    ],
                ],
            ],
        ];

        return json_encode($sarif, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
    }

    public function renderMarkdown(AuditReport $auditReport): string
    {
        return implode("\n", [
            '# Security Audit Report',
            '',
            \sprintf(
                '**Risk level:** %s (score %d) · **Findings:** %d · **Files scanned:** %d',
                $auditReport->riskLevel(),
                $auditReport->riskScore(),
                $auditReport->totalVulnerabilities(),
                $auditReport->filesScanned(),
            ),
            '',
            $this->markdownBody($auditReport),
            '',
            '---',
            '',
            \sprintf('Generated by [%s](%s).', self::PACKAGE_NAME, self::HOMEPAGE_URL),
        ]);
    }

    private function markdownBody(AuditReport $auditReport): string
    {
        if (0 === $auditReport->totalVulnerabilities()) {
            return '✅ No validated vulnerabilities found.';
        }

        $lines = ['## Summary by severity', '', '| Severity | Count |', '| --- | --- |'];

        foreach (VulnerabilitySeverity::cases() as $severity) {
            $count = \count($auditReport->vulnerabilitiesBySeverity($severity));
            if ($count > 0) {
                $lines[] = \sprintf('| %s | %d |', $severity->label(), $count);
            }
        }

        $lines[] = '';
        $lines[] = \sprintf('## Findings (%d)', $auditReport->totalVulnerabilities());

        foreach ($auditReport->vulnerabilities() as $vulnerability) {
            $lines[] = '';
            $lines[] = $this->markdownVulnerability($vulnerability);
        }

        return implode("\n", $lines);
    }

    private function markdownVulnerability(Vulnerability $vulnerability): string
    {
        return implode("\n", [
            \sprintf('### %s — %s', $vulnerability->severity()->label(), $vulnerability->title()),
            '',
            \sprintf('- **Type:** `%s` (%s)', $vulnerability->type()->value, $vulnerability->type()->owaspReference()),
            \sprintf('- **Location:** `%s:%d-%d`', $vulnerability->filePath(), $vulnerability->lineStart(), $vulnerability->lineEnd()),
            \sprintf('- **Confidence:** %s%%', \sprintf('%.0f', $vulnerability->confidence() * 100)),
            '',
            $vulnerability->description(),
            '',
            \sprintf('**Attack vector:** %s', $vulnerability->attackVector()),
            '',
            '**Proof:**',
            '',
            $this->markdownCodeBlock($vulnerability->proof()),
            '',
            \sprintf('**Remediation:** %s', $vulnerability->remediation()),
        ]);
    }

    private function markdownCodeBlock(string $text): string
    {
        return implode("\n", array_map(
            static fn (string $line): string => \sprintf('    %s', $line),
            explode("\n", $text),
        ));
    }

    private function htmlSummary(AuditReport $auditReport): string
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

    private function htmlBody(AuditReport $auditReport): string
    {
        if (0 === $auditReport->totalVulnerabilities()) {
            return '';
        }

        $cards = array_map(
            fn (Vulnerability $vulnerability): string => $this->htmlVulnerability($vulnerability),
            $auditReport->vulnerabilities(),
        );

        return \sprintf(
            '<h2>Vulnerabilities (%d total)</h2>%s',
            $auditReport->totalVulnerabilities(),
            implode('', $cards),
        );
    }

    private function htmlVulnerability(Vulnerability $vulnerability): string
    {
        return strtr($this->loadTemplate('vulnerability.html'), [
            '{{id}}' => $this->escape($vulnerability->id()),
            '{{severity}}' => $this->escape($vulnerability->severity()->label()),
            '{{severityClass}}' => $this->escape($vulnerability->severity()->value),
            '{{title}}' => $this->escape($vulnerability->title()),
            '{{owasp}}' => $this->escape($vulnerability->type()->owaspReference()),
            '{{type}}' => $this->escape($vulnerability->type()->value),
            '{{location}}' => $this->escape(\sprintf(
                '%s:%d-%d',
                $vulnerability->filePath(),
                $vulnerability->lineStart(),
                $vulnerability->lineEnd(),
            )),
            '{{description}}' => $this->escape($vulnerability->description()),
            '{{attackVector}}' => $this->escape($vulnerability->attackVector()),
            '{{proof}}' => $this->escape($vulnerability->proof()),
            '{{remediation}}' => $this->escape($vulnerability->remediation()),
            '{{confidence}}' => $this->escape(\sprintf('%.0f', $vulnerability->confidence() * 100)),
        ]);
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, \ENT_QUOTES | \ENT_SUBSTITUTE, 'UTF-8');
    }

    private function renderBody(AuditReport $auditReport): string
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
            $lines[] = $this->renderVulnerability($vulnerability);
        }

        return implode("\n", $lines);
    }

    private function renderVulnerability(Vulnerability $vulnerability): string
    {
        return strtr($this->loadTemplate('vulnerability.txt'), [
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

    private function loadTemplate(string $name): string
    {
        return u($this->filesystem->readFile(\sprintf('%s/%s/%s', __DIR__, self::TEMPLATE_DIRECTORY_NAME, $name)))->trimEnd("\n")->toString();
    }

    private function packageVersion(): string
    {
        return InstalledVersions::getPrettyVersion(self::PACKAGE_NAME) ?? self::UNKNOWN_VERSION;
    }

    private function sarifLevel(VulnerabilitySeverity $vulnerabilitySeverity): string
    {
        return match ($vulnerabilitySeverity) {
            VulnerabilitySeverity::CRITICAL, VulnerabilitySeverity::HIGH => 'error',
            VulnerabilitySeverity::MEDIUM => 'warning',
            VulnerabilitySeverity::LOW, VulnerabilitySeverity::INFO => 'note',
        };
    }
}
