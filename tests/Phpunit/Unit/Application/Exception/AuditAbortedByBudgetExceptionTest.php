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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Exception;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

final class AuditAbortedByBudgetExceptionTest extends TestCase
{
    public function test_from_carries_budget_message_and_partial_report(): void
    {
        $tmpDir = sys_get_temp_dir().'/aabe_'.uniqid('', true);
        mkdir($tmpDir, 0o777, true);
        $auditContext = AuditContext::forProject($tmpDir);
        $auditReport = AuditReport::fromContext($auditContext);
        $budgetExceededException = BudgetExceededException::forTokens(150, 100);

        $auditAbortedByBudgetException = AuditAbortedByBudgetException::from($budgetExceededException, $auditReport);

        self::assertSame('Audit aborted: token budget exceeded (150 / 100 tokens)', $auditAbortedByBudgetException->getMessage());
        self::assertSame($auditReport, $auditAbortedByBudgetException->partialReport());
        self::assertSame($budgetExceededException, $auditAbortedByBudgetException->getPrevious());

        rmdir($tmpDir);
    }
}
