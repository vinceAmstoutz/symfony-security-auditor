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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;

/**
 * Token + USD cost attribution for an audit run.
 *
 * `primaryModel` is the model used by the attacker (the dominant cost
 * contributor). When the audit ran with a split attacker/reviewer
 * configuration, the optional per-role breakdown lives in `byRole()` and is
 * also surfaced in `toArray()` under `by_role` — useful for dry-run reports
 * that want to show "$X for the attacker, $Y for the reviewer" instead of
 * a single bundled total.
 */
final readonly class AuditCost
{
    /**
     * @param array<string, array{model: string, input_tokens: int, output_tokens: int, estimated_cost_usd: float}> $byRole
     */
    private function __construct(
        private int $inputTokens,
        private int $outputTokens,
        private float $estimatedCostUsd,
        private string $primaryModel,
        private array $byRole = [],
    ) {}

    /**
     * @param array<string, array{model: string, input_tokens: int, output_tokens: int, estimated_cost_usd: float}> $byRole keyed by role name
     *                                                                                                                      (e.g. `attacker`,
     *                                                                                                                      `reviewer`); each
     *                                                                                                                      entry's totals must
     *                                                                                                                      not exceed the
     *                                                                                                                      aggregate
     *
     * @throws InvalidAuditCostException
     */
    public static function of(int $inputTokens, int $outputTokens, float $estimatedCostUsd, string $primaryModel, array $byRole = []): self
    {
        if ($inputTokens < 0) {
            throw InvalidAuditCostException::forNegativeInputTokens($inputTokens);
        }

        if ($outputTokens < 0) {
            throw InvalidAuditCostException::forNegativeOutputTokens($outputTokens);
        }

        if (!is_finite($estimatedCostUsd) || $estimatedCostUsd < 0.0) {
            throw InvalidAuditCostException::forNegativeCost($estimatedCostUsd);
        }

        return new self($inputTokens, $outputTokens, round($estimatedCostUsd, 6), $primaryModel, $byRole);
    }

    public static function zero(string $primaryModel): self
    {
        return new self(0, 0, 0.0, $primaryModel, []);
    }

    public function inputTokens(): int
    {
        return $this->inputTokens;
    }

    public function outputTokens(): int
    {
        return $this->outputTokens;
    }

    public function totalTokens(): int
    {
        return $this->inputTokens + $this->outputTokens;
    }

    public function estimatedCostUsd(): float
    {
        return $this->estimatedCostUsd;
    }

    public function primaryModel(): string
    {
        return $this->primaryModel;
    }

    /**
     * @return array<string, array{model: string, input_tokens: int, output_tokens: int, estimated_cost_usd: float}>
     */
    public function byRole(): array
    {
        return $this->byRole;
    }

    /**
     * `by_role` is cast to `object` so `json_encode()` always renders it as a
     * JSON object (`{}`), never an array (`[]`) — PHP's array type can't
     * distinguish "empty map" from "empty list", so an unqualified empty
     * array here would silently flip the field's JSON type between the
     * populated (dry-run) and unpopulated (real-run) cases, breaking any
     * strongly-typed consumer of the JSON report.
     *
     * @return array<string, int|float|string|object>
     */
    public function toArray(): array
    {
        return [
            'input_tokens' => $this->inputTokens,
            'output_tokens' => $this->outputTokens,
            'total_tokens' => $this->totalTokens(),
            'estimated_cost_usd' => $this->estimatedCostUsd,
            'primary_model' => $this->primaryModel,
            'by_role' => (object) $this->byRole,
        ];
    }
}
