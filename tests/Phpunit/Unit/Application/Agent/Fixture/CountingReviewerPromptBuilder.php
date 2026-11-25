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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;

final class CountingReviewerPromptBuilder implements ReviewerPromptBuilderInterface
{
    public int $userMessagesBuilt = 0;

    public function __construct(private readonly ReviewerPromptBuilderInterface $reviewerPromptBuilder) {}

    #[Override]
    public function buildSystemPrompt(): string
    {
        return $this->reviewerPromptBuilder->buildSystemPrompt();
    }

    #[Override]
    public function buildUserMessage(Vulnerability $vulnerability, string $codeContext): string
    {
        ++$this->userMessagesBuilt;

        return $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext);
    }

    #[Override]
    public function buildBatchSystemPrompt(): string
    {
        return $this->reviewerPromptBuilder->buildBatchSystemPrompt();
    }

    #[Override]
    public function buildBatchUserMessage(array $vulnerabilities, array $codeContexts): string
    {
        return $this->reviewerPromptBuilder->buildBatchUserMessage($vulnerabilities, $codeContexts);
    }
}
