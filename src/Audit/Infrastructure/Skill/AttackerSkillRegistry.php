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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Skill;

use Override;
use Traversable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerSkillPromptRendererInterface;

/**
 * Collects the {@see AttackerSkillInterface} strategies a framework profile
 * contributes and emits the blocks for a chunk, ordered by each skill's
 * {@see AttackerSkillInterface::priority()}.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AttackerSkillRegistry implements AttackerSkillPromptRendererInterface
{
    /** @var array<AttackerSkillInterface> */
    private array $orderedSkills;

    /**
     * @param iterable<AttackerSkillInterface> $skills the strategies a framework profile contributes
     */
    public function __construct(iterable $skills)
    {
        $ordered = $skills instanceof Traversable ? iterator_to_array($skills) : $skills;
        usort(
            $ordered,
            static fn (AttackerSkillInterface $a, AttackerSkillInterface $b): int => $a->priority() <=> $b->priority(),
        );

        $this->orderedSkills = $ordered;
    }

    /**
     * @param list<ProjectFileType> $presentTypes
     */
    #[Override]
    public function render(array $presentTypes, bool $emitAll): string
    {
        $blocks = [];
        foreach ($this->orderedSkills as $orderedSkill) {
            if ($emitAll || \in_array($orderedSkill->fileType(), $presentTypes, true)) {
                $blocks[] = $orderedSkill->block();
            }
        }

        return implode("\n\n", $blocks);
    }
}
