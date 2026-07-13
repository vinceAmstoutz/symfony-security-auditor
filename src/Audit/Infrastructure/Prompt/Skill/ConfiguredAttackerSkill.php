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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\CustomAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

use function Symfony\Component\String\u;

/**
 * Adapts a project-configured {@see CustomAttackerSkill} to the
 * {@see AttackerSkillInterface} the registry consumes: the operator's raw
 * instructions are wrapped in a `<skills role="custom:<name>">` block so they
 * sit in the prompt exactly like a built-in skill, but tagged as custom so the
 * LLM (and a human reading the prompt) can tell project rules from shipped ones.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConfiguredAttackerSkill implements AttackerSkillInterface
{
    public function __construct(
        private CustomAttackerSkill $customAttackerSkill,
    ) {}

    #[Override]
    public function fileType(): ProjectFileType
    {
        return $this->customAttackerSkill->fileType;
    }

    #[Override]
    public function priority(): int
    {
        return $this->customAttackerSkill->priority;
    }

    #[Override]
    public function block(): string
    {
        return \sprintf(
            "<skills role=\"custom:%s\">\n%s\n</skills>",
            u($this->customAttackerSkill->name)->collapseWhitespace()->toString(),
            u($this->customAttackerSkill->instructions)->trim()->toString(),
        );
    }
}
