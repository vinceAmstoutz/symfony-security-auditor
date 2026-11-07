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

/**
 * An attacker prompt builder that fits the system prompt to the audited
 * project the mapping profiled: its layout and the packages it installs.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface ProfileAwareAttackerPromptBuilderInterface extends AttackerPromptBuilderInterface
{
    /**
     * @param list<ProjectFile> $files
     */
    public function buildSystemPromptFor(array $files, SymfonyMapping $symfonyMapping): string;
}
