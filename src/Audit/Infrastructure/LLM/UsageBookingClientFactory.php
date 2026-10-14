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
 * Hands the agents a client whose usage is booked once: the bundled client
 * books its own as it goes, and a client this factory already wrapped books
 * through its wrapper — one client id wired to the other — so both are handed
 * over as they are; any other — one an application wired in place of the
 * bundled client — is wrapped so the usage its answers
 * report reaches the token totals and the audit budget, and keeps the batch
 * capabilities it has.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
