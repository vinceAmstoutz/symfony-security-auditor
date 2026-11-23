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
 * The token and USD cost of an audit run. `primaryModel` is the attacker's
 * model; `byRole()`, listed as `by_role` by `toArray()`, breaks a split
 * attacker/reviewer estimate down per role.
 */
final readonly class AuditCost
{
    /**
     * @param array<string, array{model: string, input_tokens: int, output_tokens: int, estimated_cost_usd: float}>                                                                                     $byRole
     * @param array<string, array{model: string, input_tokens: int, output_tokens: int, cache_read_tokens?: int, cache_creation_tokens?: int, estimated_cost_usd: float, billed_models?: list<string>}> $byModel
     */
    private function __construct(
        private int $inputTokens,
        private int $outputTokens,
        private float $estimatedCostUsd,
        private string $primaryModel,
        private array $byRole = [],
        private array $byModel = [],
        private int $interruptedCalls = 0,
    ) {}

    /**
     * @param array<string, array{model: string, input_tokens: int, output_tokens: int, estimated_cost_usd: float}> $byRole keyed by role name; no entry exceeds the aggregate
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
        return $this->heldAtLargestCount($this->inputTokens + $this->outputTokens);
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
     * False when tokens were spent but priced out to zero: the model has no
     * published rate or is a free local model. Zero tokens is no pricing gap.
     * Each model, or each role of a `--dry-run` estimate, is checked on its own,
     * so an unpriced reviewer beside a priced attacker is a gap.
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
     * Counts cache reads and writes, which are billed too.
     *
     * @param array{input_tokens: int, output_tokens: int, cache_read_tokens?: int, cache_creation_tokens?: int} $entry
     */
    private function billableTokens(array $entry): int
    {
        return $this->heldAtLargestCount($entry['input_tokens']
            + $entry['output_tokens']
            + ($entry['cache_read_tokens'] ?? 0)
            + ($entry['cache_creation_tokens'] ?? 0));
    }

    private function heldAtLargestCount(int|float $tokens): int
    {
        return \is_int($tokens) ? $tokens : \PHP_INT_MAX;
    }

    /**
     * @return array<string, array{model: string, input_tokens: int, output_tokens: int, estimated_cost_usd: float}>
     */
    public function byRole(): array
    {
        return $this->byRole;
    }

    /**
     * `billed_models` names the models a configured model's calls were billed
     * as, which a gateway or an alias can make differ from it.
     *
     * @param array<string, array{model: string, input_tokens: int, output_tokens: int, cache_read_tokens?: int, cache_creation_tokens?: int, estimated_cost_usd: float, billed_models?: list<string>}> $byModel keyed by model name
     */
    public function withUsageByModel(array $byModel): self
    {
        return new self($this->inputTokens, $this->outputTokens, $this->estimatedCostUsd, $this->primaryModel, $this->byRole, $byModel, $this->interruptedCalls);
    }

    /**
     * Counts the calls cut before their answer ended. A provider may bill such
     * a call beyond its reported usage, so a cost with any is a minimum.
     */
    public function withInterruptedCalls(int $interruptedCalls): self
    {
        return new self($this->inputTokens, $this->outputTokens, $this->estimatedCostUsd, $this->primaryModel, $this->byRole, $this->byModel, $interruptedCalls);
    }

    public function interruptedCalls(): int
    {
        return $this->interruptedCalls;
    }

    /**
     * `by_role` always encodes as a JSON object, `{}` when empty.
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
                    'billed_models' => $usage['billed_models'] ?? [],
                ],
                $this->byModel,
            ),
            'interrupted_calls' => $this->interruptedCalls,
        ];
    }
}
