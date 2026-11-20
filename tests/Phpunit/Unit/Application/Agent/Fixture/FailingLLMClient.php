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
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Test fake: a real LLMClientInterface implementation whose every call fails
 * with the given throwable, as a provider that aborts the run does.
 */
final readonly class FailingLLMClient implements LLMClientInterface
{
    public function __construct(
        private Throwable $throwable,
    ) {}

    /**
     * @throws Throwable
     */
    #[Override]
    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        throw $this->throwable;
    }

    /**
     * @throws Throwable
     */
    #[Override]
    public function completeWithTools(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
    {
        throw $this->throwable;
    }

    #[Override]
    public function model(): string
    {
        return 'failing';
    }
}
