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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Tool\ToolRegistry;

interface LLMClientInterface
{
    public function complete(string $systemPrompt, string $userMessage): LLMResponse;

    /**
     * Drives an autonomous tool-using conversation. Sends the initial prompts,
     * and as long as the model emits tool calls (and the iteration cap is not
     * reached), executes those tool calls via the supplied registry and feeds
     * the results back. Returns the model's final textual response once it
     * stops calling tools.
     */
    public function completeWithTools(
        string $systemPrompt,
        string $userMessage,
        ToolRegistry $toolRegistry,
        int $maxToolIterations,
    ): LLMResponse;

    public function model(): string;
}
