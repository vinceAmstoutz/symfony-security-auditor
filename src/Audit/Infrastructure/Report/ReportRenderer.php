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

    public const string UNKNOWN_VERSION = 'unknown';

    private const string TEMPLATE_DIR = __DIR__.'/Template';

    public function __construct(
        private Filesystem $filesystem = new Filesystem(),
    ) {}

    public function renderConsole(AuditReport $auditReport): string
    {
        $cost = $auditReport->cost();

        return strtr($this->loadTemplate('console.txt'), [
            '{{auditId}}' => $auditReport->auditId(),
            '{{packageName}}' => self::PACKAGE_NAME,
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
                'helpUri' => 'https://owasp.org/Top10/',
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
                            'informationUri' => 'https://github.com/vinceamstoutz/symfony-security-auditor',
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
            static fn (string $chunk): string => '    '.$chunk,
            str_split($text, 65),
        ));
    }

    private function loadTemplate(string $name): string
    {
        return u($this->filesystem->readFile(self::TEMPLATE_DIR.'/'.$name))->trimEnd("\n")->toString();
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
