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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * Test fake: a tool-batch-capable LLMClientInterface that records the user
 * message of every request it is asked to resolve, whichever way it is asked.
 */
final class RecordingBatchLLMClient implements ToolBatchCapableLLMClientInterface
{
    /** @var list<string> */
    public array $capturedUserMessages = [];

    public function __construct(
        private readonly string $responseContent = '',
    ) {}

    /**
     * @throws InvalidTokenUsageException
     */
    #[Override]
    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        $this->capturedUserMessages[] = $userMessage;

        return $this->response();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    #[Override]
    public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
    {
        $this->capturedUserMessages[] = $userMessage;

        return $this->response();
    }

    /**
     * @param list<array{system: string, user: string}> $requests
     *
     * @return list<LLMResponse>
     *
     * @throws InvalidTokenUsageException
     */
    #[Override]
    public function completeBatch(array $requests, int $maxConcurrent): array
    {
        $responses = [];
        foreach ($requests as $request) {
            $responses[] = $this->complete($request['system'], $request['user']);
        }

        return $responses;
    }

    /**
     * @param list<array{system: string, user: string, tools: ToolRegistry}> $requests
     *
     * @return list<LLMResponse>
     *
     * @throws InvalidTokenUsageException
     */
    #[Override]
    public function completeBatchWithTools(array $requests, int $maxConcurrent, int $maxToolIterations): array
    {
        $responses = [];
        foreach ($requests as $request) {
            $responses[] = $this->completeWithTools($request['system'], $request['user'], $request['tools'], $maxToolIterations);
        }

        return $responses;
    }

    #[Override]
    public function model(): string
    {
        return 'claude';
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function response(): LLMResponse
    {
        return LLMResponse::of($this->responseContent, 'claude', 'end_turn', TokenUsageSnapshot::of(1, 1));
    }
}
