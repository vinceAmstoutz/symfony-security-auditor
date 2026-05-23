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

use InvalidArgumentException;

/**
 * Token + USD cost attribution for an audit run.
 *
 * `primaryModel` is the model used by the attacker (the dominant cost
 * contributor). The reviewer may run a smaller model in split-model
 * configurations; the per-model breakdown lives in `AuditContext` if
 * downstream consumers need it.
 */
final readonly class AuditCost
{
    private function __construct(
        private int $inputTokens,
        private int $outputTokens,
        private float $estimatedCostUsd,
        private string $primaryModel,
    ) {}

    public static function of(int $inputTokens, int $outputTokens, float $estimatedCostUsd, string $primaryModel): self
    {
        if ($inputTokens < 0) {
            throw new InvalidArgumentException(\sprintf('inputTokens must be >= 0, got %d', $inputTokens));
        }

        if ($outputTokens < 0) {
            throw new InvalidArgumentException(\sprintf('outputTokens must be >= 0, got %d', $outputTokens));
        }

        if ($estimatedCostUsd < 0.0) {
            throw new InvalidArgumentException(\sprintf('estimatedCostUsd must be >= 0.0, got %f', $estimatedCostUsd));
        }

        return new self($inputTokens, $outputTokens, round($estimatedCostUsd, 6), $primaryModel);
    }

    public static function zero(string $primaryModel): self
    {
        return new self(0, 0, 0.0, $primaryModel);
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

    /** @return array<string, int|float|string> */
    public function toArray(): array
    {
        return [
            'input_tokens' => $this->inputTokens,
            'output_tokens' => $this->outputTokens,
            'total_tokens' => $this->totalTokens(),
            'estimated_cost_usd' => $this->estimatedCostUsd,
            'primary_model' => $this->primaryModel,
        ];
    }
}
