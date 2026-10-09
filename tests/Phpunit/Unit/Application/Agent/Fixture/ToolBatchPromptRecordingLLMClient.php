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
 * Test fake: a client that can batch plain and tool-using conversations and
 * logs every prompt it is given together with whether the tool registry it was
 * handed offers `record_review`.
 */
final readonly class ToolBatchPromptRecordingLLMClient implements ToolBatchCapableLLMClientInterface
{
    public function __construct(private PromptLog $promptLog) {}

    /**
     * @throws InvalidTokenUsageException
     */
    #[Override]
    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        $this->promptLog->record($systemPrompt, $userMessage, null);

        return $this->emptyResponse();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    #[Override]
    public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
    {
        $this->promptLog->record($systemPrompt, $userMessage, $toolRegistry);

        return $this->emptyResponse();
    }

    /**
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
    private function emptyResponse(): LLMResponse
    {
        return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(0, 0));
    }
}
