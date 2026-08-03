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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Report;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\GithubCommentReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;

final class GithubCommentReportRendererTest extends AbstractReportRendererTestCase
{
    #[Override]
    protected function createRenderer(): ReportRendererInterface
    {
        return new GithubCommentReportRenderer();
    }

    public function test_it_advertises_the_github_comment_format(): void
    {
        self::assertSame('github-comment', $this->renderer->format());
    }

    /**
     * The marker is what lets a workflow find its own previous comment and edit
     * it in place instead of appending a new one on every push.
     *
     * @throws InvalidAuditContextException
     */
    public function test_render_opens_with_the_find_and_update_marker(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringStartsWith(GithubCommentReportRenderer::MARKER, $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_headlines_the_grade_and_the_normalized_score(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString('## Security audit: A (100/100)', $output);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_headlines_the_degraded_grade_of_a_report_with_findings(): void
    {
        $output = $this->renderer->render($this->makeReport(
            $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::CRITICAL),
        ));

        self::assertStringContainsString('## Security audit: B (90/100)', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_reports_a_clean_project_instead_of_an_empty_table(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString('No validated vulnerabilities found.', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_a_clean_report_carries_no_findings_table(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringNotContainsString('| Severity |', $output);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_lists_a_finding_as_a_table_row(): void
    {
        $output = $this->renderer->render($this->makeReport(
            $this->makeValidatedVuln(filePath: 'src/Repository/ProductRepository.php', lineStart: 88),
        ));

        self::assertStringContainsString(
            '| 🟠 HIGH | Test Vuln | `src/Repository/ProductRepository.php:88` | `sql_injection` |',
            $output,
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_summarizes_the_run_beside_the_headline(): void
    {
        $output = $this->renderer->render($this->makeReport(
            $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::MEDIUM, filePath: 'src/A.php'),
            $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::MEDIUM, filePath: 'src/B.php'),
            $this->makeValidatedVuln(vulnerabilitySeverity: VulnerabilitySeverity::MEDIUM, filePath: 'src/C.php'),
        ));

        self::assertStringContainsString('**Risk level:** MEDIUM · **Findings:** 3', $output);
    }

    /**
     * One decimal place, matching every sibling renderer — a comment header is
     * not the place for sub-100ms precision.
     *
     * @throws InvalidAuditContextException
     */
    public function test_render_states_the_duration_to_a_single_decimal(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertMatchesRegularExpression('/\*\*Duration:\*\* \d+\.\ds/', $output);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_keeps_only_the_most_severe_findings_within_the_row_cap(): void
    {
        $output = $this->renderer->render($this->makeReport(...$this->manyFindings(
            GithubCommentReportRenderer::MAX_ROWS + 3,
        )));

        self::assertSame(
            GithubCommentReportRenderer::MAX_ROWS,
            substr_count($output, '| `sql_injection` |'),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_says_how_many_findings_the_row_cap_left_out(): void
    {
        $output = $this->renderer->render($this->makeReport(...$this->manyFindings(
            GithubCommentReportRenderer::MAX_ROWS + 3,
        )));

        self::assertStringContainsString(
            \sprintf('Showing the %d most severe of %d findings.', GithubCommentReportRenderer::MAX_ROWS, GithubCommentReportRenderer::MAX_ROWS + 3),
            $output,
        );
    }

    /**
     * Without the blank line the note would be parsed as another table row and
     * render inside the table instead of below it.
     *
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_truncation_note_is_separated_from_the_table_by_a_blank_line(): void
    {
        $output = $this->renderer->render($this->makeReport(...$this->manyFindings(
            GithubCommentReportRenderer::MAX_ROWS + 3,
        )));

        self::assertStringContainsString("|\n\n_Showing the ", $output);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_render_stays_silent_about_truncation_when_every_finding_fits(): void
    {
        $output = $this->renderer->render($this->makeReport(...$this->manyFindings(2)));

        self::assertStringNotContainsString('most severe of', $output);
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_footer_links_to_the_project_homepage(): void
    {
        $output = $this->renderer->render($this->makeReport());

        self::assertStringContainsString(
            'Generated by [vinceamstoutz/symfony-security-auditor](https://github.com/vinceamstoutz/symfony-security-auditor).',
            $output,
        );
    }

    /**
     * A `|` in an LLM-authored title would otherwise forge extra table columns.
     *
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_pipe_in_a_title_cannot_forge_a_table_column(): void
    {
        $output = $this->renderer->render($this->makeReport($this->titled('a | b')));

        self::assertStringContainsString('| a \\| b |', $output);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_newline_in_a_title_cannot_forge_a_table_row(): void
    {
        $output = $this->renderer->render($this->makeReport($this->titled("a\n| x | y | z |")));

        self::assertStringContainsString('| a \\| x \\| y \\| z \\| |', $output);
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_link_in_a_title_cannot_forge_a_clickable_link(): void
    {
        $output = $this->renderer->render($this->makeReport($this->titled('[click](https://evil.test)')));

        self::assertStringContainsString('\\[click\\](https://evil.test)', $output);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function titled(string $title): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, $title, 0.9),
            new CodeLocation('src/Foo.php', 1, 5),
            new VulnerabilityNarrative('desc', 'inject', "' OR 1=1", 'fix'),
            '$q',
        )->withReviewerValidation(true);
    }

    /**
     * @return list<Vulnerability>
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function manyFindings(int $count): array
    {
        $vulnerabilities = [];
        for ($i = 1; $i <= $count; ++$i) {
            $vulnerabilities[] = $this->makeValidatedVuln(filePath: \sprintf('src/File%d.php', $i));
        }

        return $vulnerabilities;
    }
}
