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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

/**
 * The skill block of one attack surface, added to the attacker system prompt
 * when a file of its {@see fileType()} is in the chunk.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
interface AttackerSkillInterface
{
    public function fileType(): ProjectFileType;

    /**
     * Lower is emitted earlier: a higher-risk surface declares a lower
     * priority.
     */
    public function priority(): int;

    /**
     * The `<skills role="…">…</skills>` block: the patterns to hunt and those
     * not to flag.
     */
    public function block(): string;
}
