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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception;

use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/**
 * Signals that an audit was halted because the configured token or cost budget
 * was exhausted. Carries the partial `AuditReport` collected up to the abort
 * point so the command layer can still render whatever findings were validated.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class AuditAbortedByBudgetException extends RuntimeException
{
    private function __construct(string $message, private readonly AuditReport $auditReport, BudgetExceededException $budgetExceededException)
    {
        parent::__construct($message, previous: $budgetExceededException);
    }

    public static function from(BudgetExceededException $budgetExceededException, AuditReport $auditReport): self
    {
        return new self($budgetExceededException->getMessage(), $auditReport, $budgetExceededException);
    }

    public function partialReport(): AuditReport
    {
        return $this->auditReport;
    }
}
