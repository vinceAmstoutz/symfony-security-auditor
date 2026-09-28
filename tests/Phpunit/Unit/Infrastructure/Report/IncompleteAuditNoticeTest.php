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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\IncompleteAuditNotice;

final class IncompleteAuditNoticeTest extends TestCase
{
    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_counts_the_files_that_were_never_analyzed(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->recordCoverage('attacker', 'src/A.php', 'errored');
        $auditContext->recordCoverage('attacker', 'src/B.php', 'aborted');

        self::assertStringStartsWith('Audit incomplete: 2 file(s) were never analyzed', (string) IncompleteAuditNotice::for(AuditReport::fromContext($auditContext)));
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_it_has_nothing_to_say_about_a_complete_audit(): void
    {
        $auditContext = AuditContext::forProject(sys_get_temp_dir());
        $auditContext->recordCoverage('attacker', 'src/A.php', 'analyzed');

        self::assertNull(IncompleteAuditNotice::for(AuditReport::fromContext($auditContext)));
    }
}
