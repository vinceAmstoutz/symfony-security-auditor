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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\IncompleteAuditNotice;

final class IncompleteAuditNoticeTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_it_counts_the_files_that_were_never_analyzed(): void
    {
        $auditContext = $this->contextWithAFile();
        $auditContext->recordCoverage('attacker', 'src/A.php', 'errored');
        $auditContext->recordCoverage('attacker', 'src/B.php', 'aborted');

        self::assertStringStartsWith('Audit incomplete: 2 file(s) could not be fully analyzed', (string) IncompleteAuditNotice::for(AuditReport::fromContext($auditContext)));
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    #[DataProvider('causesOfAnUnanalyzedFile')]
    public function test_its_reason_holds_whatever_left_the_file_unanalyzed(string $stage, string $status): void
    {
        $auditContext = $this->contextWithAFile();
        $auditContext->recordCoverage($stage, 'src/A.php', $status);

        self::assertSame(
            'Audit incomplete: 1 file(s) could not be fully analyzed (a scan or LLM call failed, or the run was aborted), so this report cannot vouch that the project is free of vulnerabilities.',
            IncompleteAuditNotice::for(AuditReport::fromContext($auditContext)),
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function causesOfAnUnanalyzedFile(): iterable
    {
        yield 'an attacker call that failed' => ['attacker', 'errored'];
        yield 'an abort before the attacker reached the file' => ['attacker', 'aborted'];
        yield 'a reviewer call that failed' => ['reviewer', 'errored'];
        yield 'a scan that could not read the file' => ['secret_scrubbing', 'errored'];
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_it_has_nothing_to_say_about_a_complete_audit(): void
    {
        $auditContext = $this->contextWithAFile();
        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');

        self::assertNull(IncompleteAuditNotice::for(AuditReport::fromContext($auditContext)));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_says_a_scan_that_found_no_file_has_no_verdict(): void
    {
        self::assertSame(
            'Audit incomplete: the scan found no file to audit, so this report has no verdict and cannot vouch that the project is free of vulnerabilities.',
            IncompleteAuditNotice::for(AuditReport::fromContext(AuditContext::forProject(sys_get_temp_dir()))),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    public function test_it_says_no_file_was_analyzed_by_a_cost_estimate(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->setProjectFiles([
            ProjectFile::create('src/A.php', 'src/A.php', '<?php'),
            ProjectFile::create('src/B.php', 'src/B.php', '<?php'),
            ProjectFile::create('src/C.php', 'src/C.php', '<?php'),
        ]);
        $auditContext->markAsCostEstimate();

        self::assertSame(
            'Audit incomplete: none of the 3 file(s) in scope was analyzed, because a dry run makes no LLM call, so this report cannot vouch that the project is free of vulnerabilities.',
            IncompleteAuditNotice::for(AuditReport::fromContext($auditContext)),
        );
    }

    /**
     * @throws InvalidAuditContextException
     * @throws InvalidProjectFileException
     */
    private function contextWithAFile(): AuditContext
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->setProjectFiles([ProjectFile::create('src/Foo.php', 'src/Foo.php', '<?php')]);

        return $auditContext;
    }
}
