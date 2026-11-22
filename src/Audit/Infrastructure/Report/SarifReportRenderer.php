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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\DiffHunk;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\FilePatch;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Patch\UnifiedDiff;

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class SarifReportRenderer implements ReportRendererInterface, BaselineSuppressingReportRendererInterface
{
    public function __construct(
        private ReportPackage $reportPackage = new ReportPackage(),
        private ReportPathPrefix $reportPathPrefix = new ReportPathPrefix(),
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
        $notAccepted = $this->notAcceptedByBaseline($auditReport, $baselinedFingerprints);

        $results = [];
        $typesByRule = [];

        foreach ($auditReport->vulnerabilities() as $vulnerability) {
            $typesByRule[$vulnerability->type()->owaspReference()][$vulnerability->type()->value] = $vulnerability->type();
            $results[] = $this->resultFor($vulnerability, !\array_key_exists(spl_object_id($vulnerability), $notAccepted));
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
                    'invocations' => [$this->invocation($auditReport)],
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

        return json_encode($sarif, \JSON_PRETTY_PRINT | \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_INVALID_UTF8_SUBSTITUTE | \JSON_PRESERVE_ZERO_FRACTION);
    }

    /**
     * @return array<string, mixed>
     */
    private function invocation(AuditReport $auditReport): array
    {
        $notice = IncompleteAuditNotice::for($auditReport);

        return null === $notice
            ? ['executionSuccessful' => true]
            : ['executionSuccessful' => false, 'toolExecutionNotifications' => [['level' => 'error', 'message' => ['text' => $notice]]]];
    }

    /**
     * Each baseline entry accepts one finding, as
     * AuditReport::withoutFingerprints() decides.
     *
     * @param list<string> $baselinedFingerprints
     *
     * @return array<int, int> the findings left standing, keyed by object id
     */
    private function notAcceptedByBaseline(AuditReport $auditReport, array $baselinedFingerprints): array
    {
        return array_flip(array_map(
            spl_object_id(...),
            $auditReport->withoutFingerprints($baselinedFingerprints)->vulnerabilities(),
        ));
    }

    /**
     * @return array<string, mixed>
     */
    private function resultFor(Vulnerability $vulnerability, bool $baselined): array
    {
        $result = [
            'ruleId' => $vulnerability->type()->owaspReference(),
            'level' => $this->sarifLevel($vulnerability->severity()),
            'message' => ['text' => $this->escapeEmbeddedLinkSyntax(TerminalTextSanitizer::stripControlCharacters(mb_scrub($vulnerability->title(), 'UTF-8')))],
            'partialFingerprints' => ['symfonySecurityAuditor/v1' => $vulnerability->fingerprint()],
            'locations' => [
                [
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => $this->encodeArtifactUri($this->reportPathPrefix->apply($vulnerability->filePath()))],
                        'region' => [
                            'startLine' => $vulnerability->lineStart(),
                            'endLine' => $vulnerability->lineEnd(),
                        ],
                    ],
                ],
            ],
            // GitHub Code Scanning ranks alerts by the numeric `security-severity`.
            'properties' => [
                'security-severity' => \sprintf('%.1f', $vulnerability->cvssEstimate()->baseScore()),
                'cvssV4_0Vector' => $vulnerability->cvssEstimate()->vector(),
            ],
        ];

        $fixes = $this->fixesFor($vulnerability);
        if ([] !== $fixes) {
            $result['fixes'] = $fixes;
        }

        if ($baselined) {
            $result['suppressions'] = [['kind' => 'external', 'justification' => 'Accepted via audit baseline']];
        }

        return $result;
    }

    /**
     * Returns a suggested fix that reads as a unified diff as one SARIF `fix`
     * replacing whole lines; none for a fix that does not.
     *
     * @return list<array<string, mixed>>
     */
    private function fixesFor(Vulnerability $vulnerability): array
    {
        $unifiedDiff = UnifiedDiff::parse($vulnerability->suggestedFix() ?? '');
        if (!$unifiedDiff instanceof UnifiedDiff) {
            return [];
        }

        return [[
            'description' => ['text' => 'Suggested fix'],
            'artifactChanges' => array_map($this->artifactChange(...), $unifiedDiff->filePatches),
        ]];
    }

    /**
     * @return array<string, mixed>
     */
    private function artifactChange(FilePatch $filePatch): array
    {
        return [
            'artifactLocation' => ['uri' => $this->encodeArtifactUri($this->reportPathPrefix->apply($filePatch->path))],
            'replacements' => array_map(static fn (DiffHunk $diffHunk): array => [
                'deletedRegion' => [
                    'startLine' => $diffHunk->oldStart,
                    'startColumn' => 1,
                    'endLine' => $diffHunk->oldStart + \count($diffHunk->oldLines),
                    'endColumn' => 1,
                ],
                'insertedContent' => ['text' => implode('', array_map(static fn (string $line): string => \sprintf("%s\n", $line), $diffHunk->newLines))],
            ], $filePatch->hunks),
        ];
    }

    /**
     * Escapes the backslash, then `[` and `]`, so a title cannot forge the
     * hyperlink every SARIF viewer must render in `message.text`.
     */
    private function escapeEmbeddedLinkSyntax(string $title): string
    {
        return str_replace(['\\', '[', ']'], ['\\\\', '\\[', '\\]'], $title);
    }

    /**
     * Percent-encodes each segment, so a `#` or `?` in a path is not read as
     * a URI fragment or query.
     */
    private function encodeArtifactUri(string $filePath): string
    {
        return implode('/', array_map(rawurlencode(...), explode('/', $filePath)));
    }

    private function sarifLevel(VulnerabilitySeverity $vulnerabilitySeverity): string
    {
        return SeverityLevelMapper::level($vulnerabilitySeverity, 'note');
    }

    /**
     * Names the rule after the contributing type with the lowest value, so it
     * stays stable across runs.
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
