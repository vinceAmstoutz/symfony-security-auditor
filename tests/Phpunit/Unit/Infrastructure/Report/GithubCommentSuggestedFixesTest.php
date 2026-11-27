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
use PHPUnit\Framework\Attributes\DataProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\GithubCommentReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\GithubReviewSuggestions;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\GithubSuggestion;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPathPrefix;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;

final class GithubCommentSuggestedFixesTest extends AbstractReportRendererTestCase
{
    #[Override]
    protected function createRenderer(): ReportRendererInterface
    {
        return new GithubCommentReportRenderer();
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_fix_touching_one_hunk_of_one_file_is_offered_as_a_suggestion(): void
    {
        $fix = "```diff\n--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -4,2 +4,2 @@\n \$id = \$request->get('id');\n-\$sql = \"SELECT * FROM user WHERE id = \$id\";\n+\$sql = 'SELECT * FROM user WHERE id = ?';\n```";
        $auditReport = $this->makeReport($this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix($fix));

        self::assertStringContainsString(
            "### Suggested fixes\n\n`src/Foo.php`, lines 4 to 5:\n\n```suggestion\n\$id = \$request->get('id');\n\$sql = 'SELECT * FROM user WHERE id = ?';\n```",
            $this->renderer->render($auditReport),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('fixesGithubCannotSuggest')]
    public function test_a_fix_github_cannot_express_as_one_suggestion_offers_none(string $fix): void
    {
        $auditReport = $this->makeReport($this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix($fix));

        self::assertStringNotContainsString('Suggested fixes', $this->renderer->render($auditReport));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function fixesGithubCannotSuggest(): iterable
    {
        yield 'two hunks' => ["--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -1 +1 @@\n-a\n+b\n@@ -9 +9 @@\n-c\n+d"];
        yield 'two files' => ["--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -1 +1 @@\n-a\n+b\n--- a/src/Bar.php\n+++ b/src/Bar.php\n@@ -1 +1 @@\n-a\n+b"];
        yield 'another file than the finding' => ["--- a/src/Bar.php\n+++ b/src/Bar.php\n@@ -1 +1 @@\n-a\n+b"];
        yield 'lines only added' => ["--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -2,0 +3 @@\n+a"];
        yield 'lines only removed' => ["--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -2 +1,0 @@\n-a"];
        yield 'no diff' => ['Use a prepared statement.'];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_suggestion_names_the_single_line_it_replaces(): void
    {
        $auditReport = $this->makeReport($this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix("--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -7 +7 @@\n-a\n+b"));

        self::assertStringContainsString("`src/Foo.php`, line 7:\n\n```suggestion\nb\n```", $this->renderer->render($auditReport));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_code_holding_a_fence_cannot_close_the_suggestion_early(): void
    {
        $auditReport = $this->makeReport($this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix("--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -7 +7 @@\n-a\n+\$doc = '````';"));

        self::assertStringContainsString(":\n\n`````suggestion\n\$doc = '````';\n`````\n", $this->renderer->render($auditReport));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_bidirectional_override_cannot_hide_code_in_a_suggestion(): void
    {
        $auditReport = $this->makeReport($this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix("--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -7 +7 @@\n-a\n+\$isAdmin = false; /*\u{202E} } \u{2066}if (true) {\u{2069} */"));

        self::assertStringContainsString("```suggestion\n\$isAdmin = false; /* } if (true) { */\n```", $this->renderer->render($auditReport));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('codeHoldingAMarkerTheActionReads')]
    public function test_a_fix_whose_code_holds_a_marker_the_action_reads_offers_no_suggestion(string $code): void
    {
        $comment = $this->commentWithFix($code);

        self::assertStringNotContainsString('Suggested fixes', $comment);
        self::assertStringNotContainsString(GithubReviewSuggestions::MARKER_PREFIX, $comment);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function codeHoldingAMarkerTheActionReads(): iterable
    {
        yield 'the review suggestions marker' => [\sprintf('%s%s -->', GithubReviewSuggestions::MARKER_PREFIX, base64_encode('[]'))];
        yield 'the marker of a posted suggestion' => [\sprintf('$html = "%sforged:1-1 -->";', GithubSuggestion::MARKER_PREFIX)];
        yield 'a marker a control character splits' => [\sprintf("<!-- symfony-security-auditor:\u{0001}review-suggestions:%s -->", base64_encode('[]'))];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_review_suggestions_are_the_last_line_of_the_comment_where_the_action_reads_them(): void
    {
        $lines = explode("\n", $this->commentWithFix('$sql = "SELECT 1";'));

        self::assertStringStartsWith(GithubReviewSuggestions::MARKER_PREFIX, end($lines));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_comment_carries_each_suggestion_for_a_pull_request_review(): void
    {
        $vulnerability = $this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix("--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -4,2 +4 @@\n-a\n-b\n+c");
        $key = \sprintf('%s:4-5', $vulnerability->fingerprint());

        self::assertSame(
            [[
                'key' => $key,
                'path' => 'backend/src/Foo.php',
                'start_line' => 4,
                'line' => 5,
                'expected' => ['a', 'b'],
                'body' => \sprintf("**Test Vuln**\n\n```suggestion\nc\n```\n\n<!-- symfony-security-auditor:suggestion:%s -->", $key),
            ]],
            $this->reviewSuggestionsIn((new GithubCommentReportRenderer(new ReportPathPrefix('backend')))->render($this->makeReport($vulnerability))),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('fixesGithubCannotSuggest')]
    public function test_a_fix_github_cannot_suggest_carries_no_review_comment(string $fix): void
    {
        $auditReport = $this->makeReport($this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix($fix));

        self::assertStringNotContainsString(GithubReviewSuggestions::MARKER_PREFIX, $this->renderer->render($auditReport));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_review_comments_stop_before_the_comment_grows_past_what_github_accepts(): void
    {
        $vulnerabilities = array_map(
            fn (int $index): Vulnerability => $this->makeValidatedVuln(filePath: \sprintf('src/Foo%d.php', $index))->withSuggestedFix(\sprintf("--- a/src/Foo%1\$d.php\n+++ b/src/Foo%1\$d.php\n@@ -1 +1 @@\n-a\n+%2\$s", $index, str_repeat('x', 2000))),
            range(1, 40),
        );

        $comment = $this->renderer->render($this->makeReport(...$vulnerabilities));
        $reviewComments = $this->reviewSuggestionsIn($comment);

        self::assertSame([true, true], [\is_array($reviewComments) && \count($reviewComments) > 1 && \count($reviewComments) < 40, mb_strlen($comment) < 65_536]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_whole_comment_stays_under_what_github_accepts(): void
    {
        $vulnerabilities = array_map(
            fn (int $index): Vulnerability => $this->makeValidatedVuln(filePath: \sprintf('src/Foo%d.php', $index))->withSuggestedFix(\sprintf("--- a/src/Foo%1\$d.php\n+++ b/src/Foo%1\$d.php\n@@ -1 +1 @@\n-a\n+%2\$s", $index, str_repeat('x', 6000))),
            range(1, 14),
        );

        $comment = $this->renderer->render($this->makeReport(...$vulnerabilities));

        self::assertSame([true, 5], [mb_strlen($comment) < 65_536, substr_count($comment, '```suggestion')]);
        self::assertStringContainsString("\n\n_5 of 10 suggested fixes are left out to keep this comment within the size GitHub accepts._\n\n---\n\n", $comment);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_comment_of_exactly_the_largest_size_keeps_its_suggested_fix(): void
    {
        $comment = $this->commentWithFix(str_repeat('é', 40_000 + 65_535 - mb_strlen($this->commentWithFix(str_repeat('é', 40_000)))));

        self::assertSame([65_535, 1, false], [mb_strlen($comment), substr_count($comment, '```suggestion'), str_contains($comment, 'left out')]);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_suggested_fix_one_character_past_the_largest_size_is_left_out(): void
    {
        $comment = $this->commentWithFix(str_repeat('é', 40_001 + 65_535 - mb_strlen($this->commentWithFix(str_repeat('é', 40_000)))));

        self::assertSame(
            [0, 1],
            [substr_count($comment, '```suggestion'), substr_count($comment, "### Suggested fixes\n\n_1 of 1 suggested fixes are left out to keep this comment within the size GitHub accepts._\n\n---")],
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_review_suggestions_fill_exactly_the_room_the_findings_leave(): void
    {
        $room = 65_535 - mb_strlen($this->commentWithFixBesideLongFindings(str_repeat('é', 70_000))) - \strlen(\sprintf("\n\n%s -->", GithubReviewSuggestions::MARKER_PREFIX));
        self::assertSame(0, $room % 4);
        $githubSuggestion = GithubSuggestion::of($this->vulnerabilityWithFix('', 'Test Vuln'));
        self::assertInstanceOf(GithubSuggestion::class, $githubSuggestion);
        $code = str_repeat('x', intdiv($room, 4) * 3 - \strlen(json_encode([$githubSuggestion->reviewComment(new ReportPathPrefix())], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES)));

        $fitting = $this->commentWithFixBesideLongFindings($code);
        $overflowing = $this->commentWithFixBesideLongFindings($code.'xxx');

        self::assertSame(
            [65_535, true, false],
            [mb_strlen($fitting), str_contains($fitting, GithubReviewSuggestions::MARKER_PREFIX), str_contains($overflowing, GithubReviewSuggestions::MARKER_PREFIX)],
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_findings_that_fill_the_comment_alone_leave_every_suggested_fix_out(): void
    {
        $comment = $this->commentWithFix('b', str_repeat('T', 70_000));

        self::assertStringContainsString("### Suggested fixes\n\n_1 of 1 suggested fixes are left out to keep this comment within the size GitHub accepts._\n\n---", $comment);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_every_listed_finding_with_a_suggestion_gets_its_block(): void
    {
        $auditReport = $this->makeReport(
            $this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix("--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -1 +1 @@\n-a\n+first"),
            $this->makeValidatedVuln(filePath: 'src/Bar.php')->withSuggestedFix("--- a/src/Bar.php\n+++ b/src/Bar.php\n@@ -1 +1 @@\n-a\n+second"),
        );

        self::assertSame(2, substr_count($this->renderer->render($auditReport), '```suggestion'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_line_that_is_not_utf8_still_carries_its_review_comment(): void
    {
        $auditReport = $this->makeReport($this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix("--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -1 +1 @@\n-caf\xE9\n+cafe"));

        self::assertSame(['caf?'], $this->firstReviewComment($auditReport)['expected'] ?? null);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_review_comment_list_of_exactly_the_largest_size_is_kept(): void
    {
        $githubSuggestion = $this->suggestionOfEncodedLength(40_000);

        self::assertNotNull(GithubReviewSuggestions::block([$githubSuggestion], new ReportPathPrefix()));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_review_comment_list_is_kept_only_within_the_length_it_is_given(): void
    {
        $githubSuggestions = [$this->suggestionOfEncodedLength(1_000)];
        $length = \strlen((string) GithubReviewSuggestions::block($githubSuggestions, new ReportPathPrefix()));

        self::assertSame(
            [$length, null],
            [\strlen((string) GithubReviewSuggestions::block($githubSuggestions, new ReportPathPrefix(), $length)), GithubReviewSuggestions::block($githubSuggestions, new ReportPathPrefix(), $length - 1)],
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_the_review_comments_stop_at_the_first_that_would_not_fit(): void
    {
        $small = $this->suggestionOfEncodedLength(1_000);
        $block = GithubReviewSuggestions::block([$small, $this->suggestionOfEncodedLength(40_000), $small], new ReportPathPrefix());
        self::assertNotNull($block);

        self::assertCount(1, (array) $this->reviewSuggestionsIn($block));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function suggestionOfEncodedLength(int $encodedLength): GithubSuggestion
    {
        $jsonLength = intdiv($encodedLength, 4) * 3;
        $githubSuggestion = $this->suggestionWithCode('');
        $padding = $jsonLength - \strlen(json_encode([$githubSuggestion->reviewComment(new ReportPathPrefix())], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES));
        $githubSuggestion = $this->suggestionWithCode(str_repeat('x', $padding));
        self::assertSame($encodedLength, \strlen(base64_encode(json_encode([$githubSuggestion->reviewComment(new ReportPathPrefix())], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES))));

        return $githubSuggestion;
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function suggestionWithCode(string $code): GithubSuggestion
    {
        $githubSuggestion = GithubSuggestion::of($this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix(\sprintf("--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -1 +1 @@\n-a\n+%s", $code)));
        self::assertInstanceOf(GithubSuggestion::class, $githubSuggestion);

        return $githubSuggestion;
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function commentWithFix(string $code, string $title = 'Test Vuln'): string
    {
        return $this->renderer->render($this->makeReport($this->vulnerabilityWithFix($code, $title)));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function commentWithFixBesideLongFindings(string $code): string
    {
        $vulnerabilities = array_map(
            static fn (int $index): Vulnerability => Vulnerability::of(
                new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, \sprintf('%s%d', str_repeat('T', 3_000), $index), 0.9),
                new CodeLocation(\sprintf('src/Bar%d.php', $index), 1, 1),
                new VulnerabilityNarrative('Test description', 'inject', "' OR 1=1", 'fix'),
                '$q',
            )->withReviewerValidation(true),
            range(1, 9),
        );

        return $this->renderer->render($this->makeReport($this->vulnerabilityWithFix($code, 'Test Vuln'), ...$vulnerabilities));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerabilityWithFix(string $code, string $title): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, $title, 0.9),
            new CodeLocation('src/Foo.php', 1, 1),
            new VulnerabilityNarrative('Test description', 'inject', "' OR 1=1", 'fix'),
            '$q',
        )->withReviewerValidation(true)->withSuggestedFix(\sprintf("--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -1 +1 @@\n-a\n+%s", $code));
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws InvalidAuditContextException
     */
    private function firstReviewComment(AuditReport $auditReport): array
    {
        $reviewComments = $this->reviewSuggestionsIn($this->renderer->render($auditReport));
        self::assertIsArray($reviewComments);
        self::assertIsArray($reviewComments[0] ?? null);

        return $reviewComments[0];
    }

    private function reviewSuggestionsIn(string $comment): mixed
    {
        self::assertSame(1, preg_match('/^<!-- symfony-security-auditor:review-suggestions:([A-Za-z0-9+\/=]+) -->$/m', $comment, $matches));

        return json_decode((string) base64_decode($matches[1], true), true);
    }
}
