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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;

/**
 * Sums the estimated input tokens of a set of prompts for the configured
 * model, used to pre-acquire rate-limit budget before each invocation.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PromptTokenEstimator
{
    public function __construct(
        private TokenEstimatorInterface $tokenEstimator,
        private string $model,
    ) {}

    public function estimate(string ...$prompts): int
    {
        $total = 0;
        foreach ($prompts as $prompt) {
            $total += $this->tokenEstimator->estimateTokens($prompt, $this->model);
        }

        return $total;
    }
}
