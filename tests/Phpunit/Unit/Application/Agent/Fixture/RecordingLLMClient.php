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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Test fake: a real LLMClientInterface implementation that records every user
 * message it is asked to complete and returns a fixed response, so tests can
 * assert on prompt content without mocking the LLM seam.
 */
final class RecordingLLMClient implements LLMClientInterface
{
    /** @var list<string> */
    public array $capturedUserMessages = [];

    public function __construct(
        private readonly string $responseContent = '[]',
    ) {}

    #[Override]
    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        $this->capturedUserMessages[] = $userMessage;

        return $this->response();
    }

    #[Override]
    public function completeWithTools(
        string $systemPrompt,
        string $userMessage,
        ToolRegistry $toolRegistry,
        int $maxToolIterations,
    ): LLMResponse {
        $this->capturedUserMessages[] = $userMessage;

        return $this->response();
    }

    #[Override]
    public function model(): string
    {
        return 'claude';
    }

    private function response(): LLMResponse
    {
        return LLMResponse::of($this->responseContent, 'claude', 'end_turn', TokenUsageSnapshot::of(100, 10));
    }
}
