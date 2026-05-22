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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

interface ReviewerPromptBuilderInterface
{
    public function buildSystemPrompt(): string;

    public function buildUserMessage(Vulnerability $vulnerability, string $codeContext): string;

    /**
     * System prompt used when reviewing several findings in a single LLM call.
     * Instructs the model to return a JSON array, one review object per input finding.
     */
    public function buildBatchSystemPrompt(): string;

    /**
     * Combined user message for batch review. The LLM is expected to return a JSON array of reviews
     * with the same `id` values as the input vulnerabilities, in the same order.
     *
     * @param list<Vulnerability>   $vulnerabilities
     * @param array<string, string> $codeContexts    keyed by vulnerability id
     */
    public function buildBatchUserMessage(array $vulnerabilities, array $codeContexts): string;
}
