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

use Traversable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

/**
 * Collects every {@see AttackerSkillInterface} strategy and emits the blocks
 * for a chunk, ordered by each skill's {@see AttackerSkillInterface::priority()}.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AttackerSkillRegistry
{
    /** @var array<AttackerSkillInterface> */
    private array $orderedSkills;

    /**
     * @param iterable<AttackerSkillInterface>|null $skills the DI-tagged strategies;
     *                                                      `null` uses every built-in skill
     */
    public function __construct(?iterable $skills = null)
    {
        $ordered = $skills instanceof Traversable ? iterator_to_array($skills) : ($skills ?? $this->defaultSkills());
        usort(
            $ordered,
            static fn (AttackerSkillInterface $a, AttackerSkillInterface $b): int => $a->priority() <=> $b->priority(),
        );

        $this->orderedSkills = $ordered;
    }

    /**
     * @param list<ProjectFileType> $presentTypes
     */
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

    /**
     * @return list<AttackerSkillInterface>
     */
    private function defaultSkills(): array
    {
        return [
            new ControllerAttackerSkill(),
            new ControllerFileUploadAttackerSkill(),
            new ControllerTrustBoundaryAttackerSkill(),
            new ApiResourceAttackerSkill(),
            new LiveComponentAttackerSkill(),
            new AuthenticatorAttackerSkill(),
            new LdapServiceAttackerSkill(),
            new AdminPanelAttackerSkill(),
            new VoterAttackerSkill(),
            new WebhookConsumerAttackerSkill(),
            new MessengerHandlerAttackerSkill(),
            new EventSubscriberAttackerSkill(),
            new NormalizerAttackerSkill(),
            new SchedulerAttackerSkill(),
            new FormAttackerSkill(),
            new FileUploadAttackerSkill(),
            new RepositoryAttackerSkill(),
            new EntityAttackerSkill(),
            new EntityFileUploadAttackerSkill(),
            new TemplateAttackerSkill(),
            new TwigExtensionAttackerSkill(),
            new ConfigAttackerSkill(),
            new TrustBoundaryAttackerSkill(),
            new PhpAttackerSkill(),
        ];
    }
}
