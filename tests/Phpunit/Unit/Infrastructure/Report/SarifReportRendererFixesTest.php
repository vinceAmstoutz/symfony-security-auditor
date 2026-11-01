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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPathPrefix;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\SarifReportRenderer;

final class SarifReportRendererFixesTest extends AbstractReportRendererTestCase
{
    private const string FIX = "```diff\n--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -4,2 +4,2 @@\n \$id = \$request->get('id');\n-\$sql = \"SELECT * FROM user WHERE id = \$id\";\n+\$sql = 'SELECT * FROM user WHERE id = ?';\n```";

    #[Override]
    protected function createRenderer(): ReportRendererInterface
    {
        return new SarifReportRenderer(reportPathPrefix: new ReportPathPrefix('backend'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_finding_with_a_suggested_fix_carries_it_as_a_sarif_fix(): void
    {
        $auditReport = $this->makeReport($this->makeValidatedVuln(filePath: 'src/Foo.php')->withSuggestedFix(self::FIX));

        self::assertSame(
            [[
                'description' => ['text' => 'Suggested fix'],
                'artifactChanges' => [[
                    'artifactLocation' => ['uri' => 'backend/src/Foo.php'],
                    'replacements' => [[
                        'deletedRegion' => ['startLine' => 4, 'startColumn' => 1, 'endLine' => 6, 'endColumn' => 1],
                        'insertedContent' => ['text' => "\$id = \$request->get('id');\n\$sql = 'SELECT * FROM user WHERE id = ?';\n"],
                    ]],
                ]],
            ]],
            $this->fixesOfTheFirstResult($auditReport),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_suggested_fix_that_is_no_diff_carries_no_sarif_fix(): void
    {
        $auditReport = $this->makeReport($this->makeValidatedVuln()->withSuggestedFix('Use a prepared statement.'));

        self::assertNull($this->fixesOfTheFirstResult($auditReport));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidAuditContextException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_lines_a_fix_only_adds_delete_nothing(): void
    {
        $auditReport = $this->makeReport($this->makeValidatedVuln()->withSuggestedFix("--- a/src/Foo.php\n+++ b/src/Foo.php\n@@ -2,0 +3 @@\n+\$this->denyAccessUnlessGranted('ROLE_ADMIN');"));

        self::assertSame(
            ['deletedRegion' => ['startLine' => 3, 'startColumn' => 1, 'endLine' => 3, 'endColumn' => 1], 'insertedContent' => ['text' => "\$this->denyAccessUnlessGranted('ROLE_ADMIN');\n"]],
            $this->firstReplacementOf($this->fixesOfTheFirstResult($auditReport)),
        );
    }

    private function firstReplacementOf(mixed $fixes): mixed
    {
        self::assertIsArray($fixes);
        self::assertIsArray($fixes[0] ?? null);
        self::assertIsArray($fixes[0]['artifactChanges'] ?? null);
        self::assertIsArray($fixes[0]['artifactChanges'][0] ?? null);
        self::assertIsArray($fixes[0]['artifactChanges'][0]['replacements'] ?? null);

        return $fixes[0]['artifactChanges'][0]['replacements'][0] ?? null;
    }

    private function fixesOfTheFirstResult(AuditReport $auditReport): mixed
    {
        $decoded = json_decode($this->renderer->render($auditReport), true);
        self::assertIsArray($decoded);
        self::assertIsArray($decoded['runs'] ?? null);
        self::assertIsArray($decoded['runs'][0] ?? null);
        self::assertIsArray($decoded['runs'][0]['results'] ?? null);
        self::assertIsArray($decoded['runs'][0]['results'][0] ?? null);

        return $decoded['runs'][0]['results'][0]['fixes'] ?? null;
    }
}
