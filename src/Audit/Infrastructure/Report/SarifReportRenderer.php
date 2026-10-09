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
    private const string SECURITY_TAG = 'security';

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
        $vulnerabilitiesByRule = [];

        foreach ($auditReport->vulnerabilities() as $vulnerability) {
            $vulnerabilitiesByRule[$vulnerability->type()->owaspReference()][] = $vulnerability;
            $results[] = $this->resultFor($vulnerability, !\array_key_exists(spl_object_id($vulnerability), $notAccepted));
        }

        $rules = array_values(array_map(fn (array $contributingVulnerabilities): array => $this->ruleFor($contributingVulnerabilities, $notAccepted), $vulnerabilitiesByRule));

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
     * An accepted baseline entry accepts one finding, as in
     * {@see AuditReport::withoutFingerprints()}, which decides here which
     * findings the baseline does not accept.
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
            // `security-severity` is the numeric score GitHub Code Scanning ranks alerts by; the CVSS vector rides alongside for consumers that display it.
            'properties' => [
                'security-severity' => $this->securitySeverity($vulnerability->cvssEstimate()->baseScore()),
                'cvssV4_0Vector' => $vulnerability->cvssEstimate()->vector(),
            ],
        ];

        if ($baselined) {
            $result['suppressions'] = [['kind' => 'external', 'justification' => 'Accepted via audit baseline']];
        }

        return $result;
    }

    /**
     * The SARIF 2.1.0 spec lets a plain-text `message.text` field embed a
     * CommonMark-style `[display text](target)` hyperlink, and mandates
     * that every viewer — even one with no Markdown support — render it as
     * a clickable link. `Vulnerability::title()` is free LLM-influenced
     * text with no character restrictions, so an unescaped title lets a
     * crafted finding forge a live link into a report a reviewer trusts.
     * Escaping the backslash first, then the two characters that open the
     * link syntax, neutralizes it the same way CommonMark's own
     * backslash-escape mechanism does.
     */
    private function escapeEmbeddedLinkSyntax(string $title): string
    {
        return str_replace(['\\', '[', ']'], ['\\\\', '\\[', '\\]'], $title);
    }

    /**
     * The SARIF spec requires `artifactLocation.uri` to be a valid RFC 3986
     * URI reference; a raw file path can contain `#`/`?`, which a
     * spec-compliant consumer would parse as a fragment/query delimiter
     * rather than literal path content. Percent-encoding each segment (while
     * preserving `/` as the path separator) keeps the path intact.
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
     * When multiple `VulnerabilityType`s share an OWASP category (they can
     * have different `category()` values — e.g. `broken_access_control` vs
     * `path_traversal` both under A01), the representative used for `name`
     * and `shortDescription` is picked by sorting on the type's own value so
     * it stays stable across runs instead of following whichever finding
     * happens to be most severe.
     *
     * Only the findings the baseline leaves open score the rule: an accepted
     * finding raises no alert, so it must not rank the ones that remain, and
     * a rule with nothing open carries no score.
     *
     * @param non-empty-list<Vulnerability> $contributingVulnerabilities
     * @param array<int, int>               $notAccepted                 the findings left standing, keyed by object id
     *
     * @return array<string, mixed>
     */
    private function ruleFor(array $contributingVulnerabilities, array $notAccepted): array
    {
        $contributingTypes = [];
        foreach ($contributingVulnerabilities as $contributingVulnerability) {
            $contributingTypes[$contributingVulnerability->type()->value] = $contributingVulnerability->type();
        }

        ksort($contributingTypes);
        $vulnerabilityType = reset($contributingTypes);

        $properties = ['tags' => [...array_values(array_unique(array_map($this->cweTag(...), $contributingTypes))), self::SECURITY_TAG]];

        $openVulnerabilities = array_filter($contributingVulnerabilities, static fn (Vulnerability $vulnerability): bool => \array_key_exists(spl_object_id($vulnerability), $notAccepted));
        if ([] !== $openVulnerabilities) {
            $properties['security-severity'] = $this->securitySeverity($this->highestBaseScore($openVulnerabilities));
        }

        return [
            'id' => $vulnerabilityType->owaspReference(),
            'name' => $vulnerabilityType->value,
            'shortDescription' => ['text' => $vulnerabilityType->category()],
            'helpUri' => $vulnerabilityType->owaspReferenceUrl(),
            'properties' => $properties,
        ];
    }

    /**
     * @param non-empty-array<int, Vulnerability> $vulnerabilities
     */
    private function highestBaseScore(array $vulnerabilities): float
    {
        return max(array_map(static fn (Vulnerability $vulnerability): float => $vulnerability->cvssEstimate()->baseScore(), $vulnerabilities));
    }

    private function securitySeverity(float $baseScore): string
    {
        return \sprintf('%.1f', $baseScore);
    }

    private function cweTag(VulnerabilityType $vulnerabilityType): string
    {
        return \sprintf('external/cwe/cwe-%d', $vulnerabilityType->cwe()->id());
    }
}
