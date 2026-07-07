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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SarifReportRenderer implements ReportRendererInterface, BaselineSuppressingReportRendererInterface
{
    public function __construct(
        private ReportPackage $reportPackage = new ReportPackage(),
    ) {}

    #[Override]
    public function format(): string
    {
        return 'sarif';
    }

    #[Override]
    public function render(AuditReport $auditReport): string
    {
        return $this->renderWithSuppressions($auditReport, []);
    }

    /**
     * @param list<string> $baselinedFingerprints
     */
    #[Override]
    public function renderWithSuppressions(AuditReport $auditReport, array $baselinedFingerprints): string
    {
        $vulnerabilities = $auditReport->vulnerabilities();

        $results = [];
        $typesByRule = [];

        foreach ($vulnerabilities as $vulnerability) {
            $typesByRule[$vulnerability->type()->owaspReference()][$vulnerability->type()->value] = $vulnerability->type();
            $results[] = $this->resultFor($vulnerability, $baselinedFingerprints);
        }

        $rules = array_values(array_map($this->ruleFor(...), $typesByRule));

        $cost = $auditReport->cost();
        $sarif = [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'Symfony Security Auditor',
                            'version' => $this->reportPackage->version(),
                            'informationUri' => ReportPackage::HOMEPAGE_URL,
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

        return json_encode($sarif, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_INVALID_UTF8_SUBSTITUTE);
    }

    /**
     * @param list<string> $baselinedFingerprints
     *
     * @return array<string, mixed>
     */
    private function resultFor(Vulnerability $vulnerability, array $baselinedFingerprints): array
    {
        $result = [
            'ruleId' => $vulnerability->type()->owaspReference(),
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

        if (\in_array($vulnerability->fingerprint(), $baselinedFingerprints, true)) {
            $result['suppressions'] = [['kind' => 'external', 'justification' => 'Accepted via audit baseline']];
        }

        return $result;
    }

    private function sarifLevel(VulnerabilitySeverity $vulnerabilitySeverity): string
    {
        return SeverityLevelMapper::level($vulnerabilitySeverity, 'note');
    }

    /**
     * When multiple `VulnerabilityType`s share an OWASP category (they can
     * have different `category()` values — e.g. `broken_access_control` vs
     * `path_traversal` both under A01), the representative used for `name`
     * and `shortDescription` is picked by sorting on the type's own value so
     * it stays stable across runs instead of following whichever finding
     * happens to be most severe.
     *
     * @param non-empty-array<string, VulnerabilityType> $contributingTypes
     *
     * @return array<string, mixed>
     */
    private function ruleFor(array $contributingTypes): array
    {
        ksort($contributingTypes);
        $vulnerabilityType = reset($contributingTypes);

        return [
            'id' => $vulnerabilityType->owaspReference(),
            'name' => $vulnerabilityType->value,
            'shortDescription' => ['text' => $vulnerabilityType->category()],
            'helpUri' => $vulnerabilityType->owaspReferenceUrl(),
            'properties' => ['tags' => array_values(array_unique(array_map($this->cweTag(...), $contributingTypes)))],
        ];
    }

    private function cweTag(VulnerabilityType $vulnerabilityType): string
    {
        return \sprintf('external/cwe/cwe-%d', $vulnerabilityType->cwe()->id());
    }
}
