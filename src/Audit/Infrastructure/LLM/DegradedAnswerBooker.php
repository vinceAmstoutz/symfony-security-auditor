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

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * A provider that reports an answer with nothing usable in it as an error —
 * cut off by the output limit, withheld by a content filter, or empty — still
 * bills the request it accepted, yet no usage comes back with the error. The
 * run goes on past such an answer, so its estimated input tokens are booked
 * against the budget rather than letting the cap be overrun unseen; the output
 * it produced is unknown and counted as none.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class DegradedAnswerBooker
{
    public function __construct(
        private string $model,
        private ?BudgetTracker $budgetTracker,
        private LoggerInterface $logger,
        private ?TokenUsageRecorder $tokenUsageRecorder = null,
    ) {}

    /**
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    public function book(int $estimatedInputTokens, string $stopReason): void
    {
        $this->budgetTracker?->recordCall(LLMResponse::of('', $this->model, $stopReason, TokenUsageSnapshot::of($estimatedInputTokens, 0, 0, 0)));
        $this->tokenUsageRecorder?->record($estimatedInputTokens, 0);
        $this->logger->debug('An answer the provider delivered as an error is booked at its estimated input tokens, since the provider bills the request it accepted', [
            'stop_reason' => $stopReason,
            'estimated_input_tokens' => $estimatedInputTokens,
        ]);
    }
}
