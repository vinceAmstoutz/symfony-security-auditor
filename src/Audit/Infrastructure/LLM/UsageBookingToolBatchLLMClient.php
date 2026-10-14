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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * {@see UsageBookingLLMClient} for a tool-batch-capable client, which it stays.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class UsageBookingToolBatchLLMClient implements ToolBatchCapableLLMClientInterface, UsageBookingLLMClientInterface
{
    private UsageBookingBatchLLMClient $usageBookingBatchLLMClient;

    public function __construct(
        private ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient,
        private ClientUsageBooker $clientUsageBooker,
    ) {
        $this->usageBookingBatchLLMClient = new UsageBookingBatchLLMClient($toolBatchCapableLLMClient, $clientUsageBooker);
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    #[Override]
    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        return $this->usageBookingBatchLLMClient->complete($systemPrompt, $userMessage);
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    #[Override]
    public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
    {
        return $this->usageBookingBatchLLMClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $maxToolIterations);
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    #[Override]
    public function completeBatch(array $requests, int $maxConcurrent): array
    {
        return $this->usageBookingBatchLLMClient->completeBatch($requests, $maxConcurrent);
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    #[Override]
    public function completeBatchWithTools(array $requests, int $maxConcurrent, int $maxToolIterations): array
    {
        $this->clientUsageBooker->beforeCall();

        return $this->clientUsageBooker->book($this->toolBatchCapableLLMClient->completeBatchWithTools($requests, $maxConcurrent, $maxToolIterations));
    }

    #[Override]
    public function model(): string
    {
        return $this->toolBatchCapableLLMClient->model();
    }
}
