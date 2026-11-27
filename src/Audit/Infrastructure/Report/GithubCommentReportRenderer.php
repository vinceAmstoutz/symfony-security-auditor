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

/**
 * Renders an audit report as a pull-request comment body: the grade, then
 * the `MAX_ROWS` most severe findings and as many of their suggested fixes as
 * keep the body under GitHub's comment length limit, naming those left out.
 * `MARKER` lets a workflow find and edit its previous comment.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class GithubCommentReportRenderer implements ReportRendererInterface
{
    /**
     * Invisible in the rendered body, found in the raw one.
     */
    public const string MARKER = '<!-- symfony-security-auditor:pr-comment -->';

    public const int MAX_ROWS = 10;

    private const int MAXIMUM_LENGTH = 65_535;

    private const string SUGGESTED_FIXES_HEADING = '### Suggested fixes';

    private const string LEFT_OUT_FIXES_NOTE = '_%d of %d suggested fixes are left out to keep this comment within the size GitHub accepts._';

    public function __construct(
        private ReportPathPrefix $reportPathPrefix = new ReportPathPrefix(),
    ) {}

    #[Override]
    public function format(): string
    {
        return 'github-comment';
    }

    #[Override]
    public function render(AuditReport $auditReport): string
    {
        $head = [self::MARKER, $this->headline($auditReport), $this->runSummary($auditReport), ...$this->findings($auditReport)];
        $sections = array_map(
            static fn (GithubSuggestion $githubSuggestion): string => $githubSuggestion->commentSection(),
            $this->suggestionsOf(\array_slice($auditReport->vulnerabilities(), 0, self::MAX_ROWS)),
        );
        $tail = ['---', $this->credit()];
        $reviewSuggestions = GithubReviewSuggestions::block(
            $this->suggestionsOf($auditReport->vulnerabilities()),
            $this->reportPathPrefix,
            self::MAXIMUM_LENGTH - $this->lengthOf([...$head, ...$this->suggestedFixes($sections, 0), ...$tail, '']),
        );
        $tail = [...$tail, ...(null === $reviewSuggestions ? [] : [$reviewSuggestions])];

        $parts = [];
        foreach (range(\count($sections), 0) as $kept) {
            $parts = [...$head, ...$this->suggestedFixes($sections, $kept), ...$tail];
            if ($this->lengthOf($parts) <= self::MAXIMUM_LENGTH) {
                break;
            }
        }

        return implode("\n\n", $parts);
    }

    /**
     * @param list<string> $parts
     */
    private function lengthOf(array $parts): int
    {
        return mb_strlen(implode("\n\n", $parts));
    }

    private function headline(AuditReport $auditReport): string
    {
        if ($auditReport->isWithoutVerdict()) {
            return '## Security audit: incomplete (no file was analyzed)';
        }

        return \sprintf(
            $auditReport->isComplete() ? '## Security audit: %s (%d/100)' : '## Security audit: incomplete (%s, %d/100 on the files analyzed)',
            $auditReport->grade()->value,
            $auditReport->normalizedScore(),
        );
    }

    private function runSummary(AuditReport $auditReport): string
    {
        return \sprintf(
            '**Risk level:** %s · **Findings:** %d · **Files scanned:** %d · **Duration:** %ss',
            RiskHeadline::riskLevel($auditReport),
            $auditReport->totalVulnerabilities(),
            $auditReport->filesScanned(),
            number_format($auditReport->durationSeconds(), 1, '.', ''),
        );
    }

    /**
     * @return list<string>
     */
    private function findings(AuditReport $auditReport): array
    {
        $notice = IncompleteAuditNotice::for($auditReport);
        $warning = null === $notice ? [] : [\sprintf('> ⚠️ **%s**', $notice)];
        $vulnerabilities = $auditReport->vulnerabilities();
        if ([] === $vulnerabilities) {
            return [] === $warning ? ['✅ No validated vulnerabilities found.'] : $warning;
        }

        $shown = \array_slice($vulnerabilities, 0, self::MAX_ROWS);

        return [
            ...$warning,
            $this->table($shown),
            ...$this->truncationNote(\count($shown), \count($vulnerabilities)),
        ];
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     */
    private function table(array $vulnerabilities): string
    {
        return implode("\n", [
            '| Severity | Finding | Location | Type |',
            '| --- | --- | --- | --- |',
            ...array_map($this->row(...), $vulnerabilities),
        ]);
    }

    private function row(Vulnerability $vulnerability): string
    {
        return \sprintf(
            '| %s | %s | %s | %s |',
            $vulnerability->severity()->label(),
            MarkdownTextEscaper::tableCell($vulnerability->title()),
            MarkdownTextEscaper::tableInlineCode(\sprintf('%s:%d', $vulnerability->filePath(), $vulnerability->lineStart())),
            MarkdownTextEscaper::tableInlineCode($vulnerability->type()->value),
        );
    }

    /**
     * @return list<string>
     */
    private function truncationNote(int $shown, int $total): array
    {
        if ($shown === $total) {
            return [];
        }

        return [\sprintf('_Showing the %d most severe of %d findings._', $shown, $total)];
    }

    /**
     * @param list<string> $sections
     *
     * @return list<string>
     */
    private function suggestedFixes(array $sections, int $kept): array
    {
        if ([] === $sections) {
            return [];
        }

        $leftOut = \count($sections) - $kept;

        return [self::SUGGESTED_FIXES_HEADING, ...\array_slice($sections, 0, $kept), ...(0 === $leftOut ? [] : [\sprintf(self::LEFT_OUT_FIXES_NOTE, $leftOut, \count($sections))])];
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     *
     * @return list<GithubSuggestion>
     */
    private function suggestionsOf(array $vulnerabilities): array
    {
        return array_values(array_filter(array_map(GithubSuggestion::of(...), $vulnerabilities), static fn (?GithubSuggestion $githubSuggestion): bool => $githubSuggestion instanceof GithubSuggestion));
    }

    private function credit(): string
    {
        return \sprintf('Generated by [%s](%s).', ReportPackage::NAME, ReportPackage::HOMEPAGE_URL);
    }
}
