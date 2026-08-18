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
     * `false` when tokens were actually spent but the total still priced out
     * to zero — the model has no published rate in the pricing catalog, or is
     * a free local/self-hosted model. Zero tokens (nothing tracked yet) is
     * not treated as a pricing gap.
     *
     * With a split attacker/reviewer configuration, the aggregate total can
     * price out nonzero even when one role's own model is unpriced — e.g. a
     * priced cloud attacker paired with an unpriced local reviewer. `byRole()`
     * carries each role's own tokens and cost, so each role is checked on its
     * own terms instead of the misleading total.
     */
    public function hasPublishedPricing(): bool
    {
        if ([] === $this->byRole) {
            return 0.0 !== $this->estimatedCostUsd || 0 === $this->totalTokens();
        }

        foreach ($this->byRole as $entry) {
            $roleTokens = $entry['input_tokens'] + $entry['output_tokens'];
            if (0.0 === $entry['estimated_cost_usd'] && 0 !== $roleTokens) {
                return false;
            }
        }

        return true;
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
