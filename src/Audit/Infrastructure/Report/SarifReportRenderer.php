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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SarifReportRenderer implements ReportRendererInterface
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
                'properties' => ['tags' => [self::cweTag($vulnerabilityType)]],
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

        return json_encode($sarif, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
    }

    private function sarifLevel(VulnerabilitySeverity $vulnerabilitySeverity): string
    {
        return match ($vulnerabilitySeverity) {
            VulnerabilitySeverity::CRITICAL, VulnerabilitySeverity::HIGH => 'error',
            VulnerabilitySeverity::MEDIUM => 'warning',
            VulnerabilitySeverity::LOW, VulnerabilitySeverity::INFO => 'note',
        };
    }

    private static function cweTag(VulnerabilityType $vulnerabilityType): string
    {
        return \sprintf('external/cwe/cwe-%s', substr($vulnerabilityType->cweReference(), 4));
    }
}
