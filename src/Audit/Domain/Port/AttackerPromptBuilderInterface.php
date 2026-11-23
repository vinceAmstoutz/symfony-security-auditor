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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;

interface AttackerPromptBuilderInterface
{
    /**
     * @param list<ProjectFile> $files the chunk's files, whose types pick the expert
     *                                 skills; empty gives the base prompt
     */
    public function buildSystemPrompt(array $files = []): string;

    /**
     * @param list<ProjectFile> $files
     */
    public function buildUserMessage(array $files, SymfonyMapping $symfonyMapping): string;
}
