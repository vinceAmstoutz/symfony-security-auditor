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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\GithubCommentReportRenderer;
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

        self::assertStringContainsString("`````suggestion\n\$doc = '````';\n`````", $this->renderer->render($auditReport));
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
}
