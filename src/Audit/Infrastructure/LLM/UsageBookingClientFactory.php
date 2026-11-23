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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * Hands the agents a client whose usage is booked once. Returns the bundled
 * client and one already wrapped as they are; wraps any other so its usage
 * reaches the token totals and the budget, keeping its batch capabilities.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class UsageBookingClientFactory
{
    public static function around(LLMClientInterface $llmClient, TokenUsageRecorder $tokenUsageRecorder, BudgetTracker $budgetTracker, UnpricedCostCapWarning $unpricedCostCapWarning): LLMClientInterface
    {
        if ($llmClient instanceof UsageBookingLLMClientInterface) {
            return $llmClient;
        }

        $clientUsageBooker = new ClientUsageBooker($tokenUsageRecorder, $budgetTracker, $unpricedCostCapWarning);

        return match (true) {
            $llmClient instanceof ToolBatchCapableLLMClientInterface => new UsageBookingToolBatchLLMClient($llmClient, $clientUsageBooker),
            $llmClient instanceof BatchCapableLLMClientInterface => new UsageBookingBatchLLMClient($llmClient, $clientUsageBooker),
            default => new UsageBookingLLMClient($llmClient, $clientUsageBooker),
        };
    }
}
