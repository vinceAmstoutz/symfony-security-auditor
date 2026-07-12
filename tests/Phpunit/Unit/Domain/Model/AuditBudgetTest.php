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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
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

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_tokens_sets_only_token_cap(): void
    {
        $auditBudget = AuditBudget::forTokens(50_000);

        self::assertFalse($auditBudget->isUnlimited());
        self::assertSame(50_000, $auditBudget->maxTokens());
        self::assertNull($auditBudget->maxCostUsd());
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_cost_sets_only_cost_cap(): void
    {
        $auditBudget = AuditBudget::forCost(2.50);

        self::assertFalse($auditBudget->isUnlimited());
        self::assertNull($auditBudget->maxTokens());
        self::assertSame(2.50, $auditBudget->maxCostUsd());
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_both_sets_both_caps(): void
    {
        $auditBudget = AuditBudget::forBoth(10_000, 1.00);

        self::assertSame(10_000, $auditBudget->maxTokens());
        self::assertSame(1.00, $auditBudget->maxCostUsd());
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_tokens_rejects_zero(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);
        $this->expectExceptionMessage('maxTokens must be > 0, got 0');

        AuditBudget::forTokens(0);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_cost_rejects_zero(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);
        $this->expectExceptionMessageMatches('/^maxCostUsd must be > 0\.0, got 0\.000000$/');

        AuditBudget::forCost(0.0);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_both_rejects_zero_tokens(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);
        $this->expectExceptionMessage('maxTokens must be > 0');

        AuditBudget::forBoth(0, 1.0);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_both_rejects_zero_cost(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);
        $this->expectExceptionMessage('maxCostUsd must be > 0.0');

        AuditBudget::forBoth(100, 0.0);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_tokens_accepts_one_at_boundary(): void
    {
        // Pins `<= 0` boundary — mutation to `< 0` would still accept 1, but
        // mutation to `> 0` would reject 1.
        $auditBudget = AuditBudget::forTokens(1);

        self::assertSame(1, $auditBudget->maxTokens());
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_cost_accepts_tiny_positive_at_boundary(): void
    {
        // Pins `<= 0.0` boundary — mutation to `> 0.0` would reject this.
        $auditBudget = AuditBudget::forCost(0.000001);

        self::assertSame(0.000001, $auditBudget->maxCostUsd());
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_both_accepts_tiny_positives_at_boundary(): void
    {
        $auditBudget = AuditBudget::forBoth(1, 0.000001);

        self::assertSame(1, $auditBudget->maxTokens());
        self::assertSame(0.000001, $auditBudget->maxCostUsd());
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_tokens_rejects_negative(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);
        $this->expectExceptionMessage('maxTokens must be > 0, got -1');

        AuditBudget::forTokens(-1);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_cost_rejects_negative(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);
        $this->expectExceptionMessage('maxCostUsd must be > 0.0');

        AuditBudget::forCost(-0.5);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_cost_rejects_nan(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);

        AuditBudget::forCost(\NAN);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_both_rejects_nan_cost(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);

        AuditBudget::forBoth(100, \NAN);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_cost_rejects_infinite(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);

        AuditBudget::forCost(\INF);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_for_both_rejects_infinite_cost(): void
    {
        $this->expectException(InvalidAuditBudgetException::class);

        AuditBudget::forBoth(100, \INF);
    }

    public function test_for_cost_rejects_negative_and_formats_the_value_with_a_period_regardless_of_the_process_numeric_locale(): void
    {
        $previousLocale = setlocale(\LC_NUMERIC, '0');
        setlocale(\LC_NUMERIC, 'de_DE.UTF-8');

        try {
            $message = '';
            try {
                AuditBudget::forCost(-0.5);
            } catch (InvalidAuditBudgetException $invalidAuditBudgetException) {
                $message = $invalidAuditBudgetException->getMessage();
            }
        } finally {
            setlocale(\LC_NUMERIC, false !== $previousLocale ? $previousLocale : 'C');
        }

        self::assertStringContainsString('got -0.500000', $message);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_is_unlimited_returns_false_when_token_cap_set(): void
    {
        // Pins the logical-and on `null === $maxTokens && null === $maxCostUsd`.
        $auditBudget = AuditBudget::forTokens(100);

        self::assertFalse($auditBudget->isUnlimited());
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_is_unlimited_returns_false_when_cost_cap_set(): void
    {
        $auditBudget = AuditBudget::forCost(1.0);

        self::assertFalse($auditBudget->isUnlimited());
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public function test_is_unlimited_returns_false_when_both_caps_set(): void
    {
        $auditBudget = AuditBudget::forBoth(100, 1.0);

        self::assertFalse($auditBudget->isUnlimited());
    }
}
