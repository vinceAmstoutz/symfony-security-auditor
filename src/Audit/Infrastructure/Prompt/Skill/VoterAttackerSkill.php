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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class VoterAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::VOTER;
    }

    #[Override]
    public function priority(): int
    {
        return 50;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="voter">
            Hunt:
            - `supports($attribute, $subject)` mismatched with attributes consumers actually pass (typo → silent allow).
            - `voteOnAttribute()` default branch returning `true` or implicit fallthrough — critical bypass.
            - Over-broad role shortcuts (`ROLE_SUPER_ADMIN` always allowed) without auditable trail.
            - Ownership checks with nullable / weak-typed comparisons (`==` on UUID strings, missing user object check).
            - Voters consulting only `getRoles()` while the request requires per-resource attribute checks.
            Do NOT flag:
            - Voters that explicitly `return false` as the default — that is the secure-by-default pattern.
            - Voters using `Security::isGranted('ROLE_USER')` after a positive ownership check.
            </skills>
            SKILL;
    }
}
