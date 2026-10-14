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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Wraps a client that does not book its own usage so each answer it gives is
 * booked through {@see ClientUsageBooker}.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class UsageBookingLLMClient implements UsageBookingLLMClientInterface
{
    public function __construct(
        private LLMClientInterface $llmClient,
        private ClientUsageBooker $clientUsageBooker,
    ) {}

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    #[Override]
    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        $this->clientUsageBooker->beforeCall();

        return $this->clientUsageBooker->book([$this->llmClient->complete($systemPrompt, $userMessage)])[0];
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     */
    #[Override]
    public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
    {
        $this->clientUsageBooker->beforeCall();

        return $this->clientUsageBooker->book([$this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $maxToolIterations)])[0];
    }

    #[Override]
    public function model(): string
    {
        return $this->llmClient->model();
    }
}
