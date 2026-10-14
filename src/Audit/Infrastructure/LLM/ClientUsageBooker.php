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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

/**
 * Books the usage the answers of a client that does not book it itself
 * report — into the run's token totals and the audit budget — and stops the
 * run once the budget is spent, checking it before and after each call as the
 * bundled client does. A cost cap holds only for a model the pricing catalog
 * prices, which {@see UnpricedCostCapWarning} says once per model.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ClientUsageBooker
{
    public function __construct(
        private TokenUsageRecorder $tokenUsageRecorder,
        private BudgetTracker $budgetTracker,
        private UnpricedCostCapWarning $unpricedCostCapWarning,
    ) {}

    /**
     * @throws BudgetExceededException
     */
    public function beforeCall(): void
    {
        $this->budgetTracker->assertWithinBudget();
    }

    /**
     * @param list<LLMResponse> $llmResponses
     *
     * @return list<LLMResponse>
     *
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    public function book(array $llmResponses): array
    {
        foreach ($llmResponses as $llmResponse) {
            $this->tokenUsageRecorder->record($llmResponse->inputTokens(), $llmResponse->outputTokens(), $llmResponse->cacheReadTokens(), $llmResponse->cacheCreationTokens());
            $this->budgetTracker->recordCall($llmResponse);
            $this->unpricedCostCapWarning->check($llmResponse);
        }

        $this->budgetTracker->assertWithinBudget();

        return $llmResponses;
    }
}
