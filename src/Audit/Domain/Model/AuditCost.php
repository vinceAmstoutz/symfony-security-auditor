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
     * @param array<string, array{model: string, input_tokens: int, output_tokens: int, estimated_cost_usd: float}>                                                       $byRole
     * @param array<string, array{model: string, input_tokens: int, output_tokens: int, cache_read_tokens?: int, cache_creation_tokens?: int, estimated_cost_usd: float}> $byModel
     */
    private function __construct(
        private int $inputTokens,
        private int $outputTokens,
        private float $estimatedCostUsd,
        private string $primaryModel,
        private array $byRole = [],
        private array $byModel = [],
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
     * `false` when tokens were actually spent but they priced out to zero —
     * the model has no published rate in the pricing catalog, or is a free
     * local/self-hosted model. Zero tokens (nothing tracked yet) is not
     * treated as a pricing gap.
     *
     * The aggregate total cannot answer this for a split configuration: a
     * priced cloud attacker paired with an unpriced local reviewer still sums
     * to something nonzero. So each breakdown is checked on its own terms
     * where one exists — the per-model map for a real run, which records the model
     * of every call, and `byRole()` for the `--dry-run` estimate, which
     * projects per role. The aggregate is the last resort, correct on its own
     * terms because a single-model run has nothing to disaggregate.
     */
    public function hasPublishedPricing(): bool
    {
        $breakdown = [] !== $this->byModel ? $this->byModel : $this->byRole;

        if ([] === $breakdown) {
            return 0.0 !== $this->estimatedCostUsd || 0 === $this->totalTokens();
        }

        foreach ($breakdown as $entry) {
            if (0.0 === $entry['estimated_cost_usd'] && 0 !== $this->billableTokens($entry)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Cache reads and cache writes are billed, so a model whose whole spend
     * arrived as cached prompt tokens has still been charged for. Counting
     * only fresh input/output would read that as "nothing spent" and hide a
     * pricing gap. The per-role dry-run breakdown projects no cache traffic,
     * so those keys are absent there.
     *
     * @param array{input_tokens: int, output_tokens: int, cache_read_tokens?: int, cache_creation_tokens?: int} $entry
     */
    private function billableTokens(array $entry): int
    {
        return $entry['input_tokens']
            + $entry['output_tokens']
            + ($entry['cache_read_tokens'] ?? 0)
            + ($entry['cache_creation_tokens'] ?? 0);
    }

    /**
     * @return array<string, array{model: string, input_tokens: int, output_tokens: int, estimated_cost_usd: float}>
     */
    public function byRole(): array
    {
        return $this->byRole;
    }

    /**
     * A real run records the model of every call but not the agent that made
     * it, so per-model is the finest attribution it can offer. Applied
     * copy-on-write rather than through `of()`, which is already at the
     * project's five-parameter ceiling.
     *
     * @param array<string, array{model: string, input_tokens: int, output_tokens: int, cache_read_tokens?: int, cache_creation_tokens?: int, estimated_cost_usd: float}> $byModel keyed by model name
     */
    public function withUsageByModel(array $byModel): self
    {
        return new self($this->inputTokens, $this->outputTokens, $this->estimatedCostUsd, $this->primaryModel, $this->byRole, $byModel);
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
            'by_model' => (object) array_map(
                static fn (array $usage): array => [
                    ...$usage,
                    'cache_read_tokens' => $usage['cache_read_tokens'] ?? 0,
                    'cache_creation_tokens' => $usage['cache_creation_tokens'] ?? 0,
                    'estimated_cost_usd' => round($usage['estimated_cost_usd'], 6),
                ],
                $this->byModel,
            ),
        ];
    }
}
