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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * {@see UsageBookingLLMClient} for a batch-capable client, which it stays.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class UsageBookingBatchLLMClient implements BatchCapableLLMClientInterface, UsageBookingLLMClientInterface
{
    private UsageBookingLLMClient $usageBookingLLMClient;

    public function __construct(
        private BatchCapableLLMClientInterface $batchCapableLLMClient,
        private ClientUsageBooker $clientUsageBooker,
    ) {
        $this->usageBookingLLMClient = new UsageBookingLLMClient($batchCapableLLMClient, $clientUsageBooker);
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    #[Override]
    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        return $this->usageBookingLLMClient->complete($systemPrompt, $userMessage);
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    #[Override]
    public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
    {
        return $this->usageBookingLLMClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $maxToolIterations);
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    #[Override]
    public function completeBatch(array $requests, int $maxConcurrent): array
    {
        $this->clientUsageBooker->beforeCall();

        return $this->clientUsageBooker->book($this->batchCapableLLMClient->completeBatch($requests, $maxConcurrent));
    }

    #[Override]
    public function model(): string
    {
        return $this->batchCapableLLMClient->model();
    }
}
