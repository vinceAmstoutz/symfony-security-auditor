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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;

/**
 * Builds the coverage critic's prompts: a summary of the audit so far — the
 * routes and their guards, the voters, the file groups the attacker analyzed
 * with their coverage status, and the findings — and never a file's contents.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface CoverageCriticPromptBuilderInterface
{
    public function buildSystemPrompt(int $maxGaps, bool $structuredCollection): string;

    /**
     * @param list<list<ProjectFile>> $fileGroups
     */
    public function buildUserMessage(SymfonyMapping $symfonyMapping, array $fileGroups, AuditContext $auditContext): string;
}
