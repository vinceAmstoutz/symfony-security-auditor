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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
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
