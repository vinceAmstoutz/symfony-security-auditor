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
     * The system prompt of a batch review, which asks for a JSON array of one
     * review per finding.
     */
    public function buildBatchSystemPrompt(): string;

    /**
     * Reviews are matched back to findings by `id`, in any order.
     *
     * @param list<Vulnerability>   $vulnerabilities
     * @param array<string, string> $codeContexts    keyed by vulnerability id
     */
    public function buildBatchUserMessage(array $vulnerabilities, array $codeContexts): string;
}
