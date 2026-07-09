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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;

/**
 * Immutable budget constraint for an audit run.
 *
 * `null` for either limit means "no cap" on that dimension. Use named factories
 * to express intent at the construction site (`unlimited()`, `forTokens()`,
 * `forCost()`, `forBoth()`) instead of remembering positional arguments.
 */
final readonly class AuditBudget
{
    private function __construct(
        private ?int $maxTokens,
        private ?float $maxCostUsd,
    ) {}

    public static function unlimited(): self
    {
        return new self(null, null);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public static function forTokens(int $maxTokens): self
    {
        return self::assertPositive($maxTokens);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public static function forCost(float $maxCostUsd): self
    {
        return self::assertPositiveCost($maxCostUsd);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    public static function forBoth(int $maxTokens, float $maxCostUsd): self
    {
        if ($maxTokens <= 0) {
            throw InvalidAuditBudgetException::forNonPositiveTokens($maxTokens);
        }

        if (!is_finite($maxCostUsd) || $maxCostUsd <= 0.0) {
            throw InvalidAuditBudgetException::forNonPositiveCost($maxCostUsd);
        }

        return new self($maxTokens, $maxCostUsd);
    }

    public function maxTokens(): ?int
    {
        return $this->maxTokens;
    }

    public function maxCostUsd(): ?float
    {
        return $this->maxCostUsd;
    }

    public function isUnlimited(): bool
    {
        return null === $this->maxTokens && null === $this->maxCostUsd;
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    private static function assertPositive(int $value): self
    {
        if ($value <= 0) {
            throw InvalidAuditBudgetException::forNonPositiveTokens($value);
        }

        return new self($value, null);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    private static function assertPositiveCost(float $value): self
    {
        if (!is_finite($value) || $value <= 0.0) {
            throw InvalidAuditBudgetException::forNonPositiveCost($value);
        }

        return new self(null, $value);
    }
}
