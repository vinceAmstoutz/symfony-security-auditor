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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Bundle\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Test fake: a decorator an application wraps around the bundled client, as
 * one adding logging or tracing would.
 */
final readonly class PassThroughLLMClient implements LLMClientInterface
{
    public function __construct(
        private LLMClientInterface $llmClient,
    ) {}

    #[Override]
    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        return $this->llmClient->complete($systemPrompt, $userMessage);
    }

    #[Override]
    public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
    {
        return $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $maxToolIterations);
    }

    #[Override]
    public function model(): string
    {
        return $this->llmClient->model();
    }
}
