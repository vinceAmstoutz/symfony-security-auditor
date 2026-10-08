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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;

final class CountingAttackerPromptBuilder implements AttackerPromptBuilderInterface
{
    public int $userMessagesBuilt = 0;

    private readonly AttackerPromptBuilder $attackerPromptBuilder;

    public function __construct()
    {
        $this->attackerPromptBuilder = new AttackerPromptBuilder();
    }

    #[Override]
    public function buildSystemPrompt(array $files = []): string
    {
        return $this->attackerPromptBuilder->buildSystemPrompt($files);
    }

    #[Override]
    public function buildUserMessage(array $files, SymfonyMapping $symfonyMapping): string
    {
        ++$this->userMessagesBuilt;

        return $this->attackerPromptBuilder->buildUserMessage($files, $symfonyMapping);
    }
}
