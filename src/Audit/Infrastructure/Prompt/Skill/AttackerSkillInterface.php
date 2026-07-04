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
 * One implementation per attack surface. Each strategy owns the expert skill
 * block injected into the attacker system prompt when a file of its
 * {@see fileType()} appears in the chunk. The `AttackerSkillRegistry` collects
 * every implementation and emits them ordered by {@see priority()}.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface AttackerSkillInterface
{
    public function fileType(): ProjectFileType;

    /**
     * Emission rank — lower is emitted earlier. The LLM weights
     * earlier-in-context instructions more heavily (primacy), so higher-risk
     * surfaces declare a lower priority.
     */
    public function priority(): int;

    /**
     * The `<skills role="…">…</skills>` block, listing both patterns to hunt
     * and patterns explicitly NOT to flag.
     */
    public function block(): string;
}
