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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;

final class AuditBudgetTest extends TestCase
{
    public function test_unlimited_has_no_caps(): void
    {
        $auditBudget = AuditBudget::unlimited();

        self::assertTrue($auditBudget->isUnlimited());
        self::assertNull($auditBudget->maxTokens());
        self::assertNull($auditBudget->maxCostUsd());
    }

    public function test_for_tokens_sets_only_token_cap(): void
    {
        $auditBudget = AuditBudget::forTokens(50_000);

        self::assertFalse($auditBudget->isUnlimited());
        self::assertSame(50_000, $auditBudget->maxTokens());
        self::assertNull($auditBudget->maxCostUsd());
    }

    public function test_for_cost_sets_only_cost_cap(): void
    {
        $auditBudget = AuditBudget::forCost(2.50);

        self::assertFalse($auditBudget->isUnlimited());
        self::assertNull($auditBudget->maxTokens());
        self::assertSame(2.50, $auditBudget->maxCostUsd());
    }

    public function test_for_both_sets_both_caps(): void
    {
        $auditBudget = AuditBudget::forBoth(10_000, 1.00);

        self::assertSame(10_000, $auditBudget->maxTokens());
        self::assertSame(1.00, $auditBudget->maxCostUsd());
    }

    public function test_for_tokens_rejects_zero(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('maxTokens must be > 0, got 0');

        AuditBudget::forTokens(0);
    }

    public function test_for_cost_rejects_zero(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('maxCostUsd must be > 0.0');

        AuditBudget::forCost(0.0);
    }

    public function test_for_both_rejects_zero_tokens(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('maxTokens must be > 0');

        AuditBudget::forBoth(0, 1.0);
    }

    public function test_for_both_rejects_zero_cost(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('maxCostUsd must be > 0.0');

        AuditBudget::forBoth(100, 0.0);
    }
}
