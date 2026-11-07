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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt\Skill\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillInterface;

final readonly class FixedBlockAttackerSkill implements AttackerSkillInterface
{
    public function __construct(
        private string $block,
    ) {}

    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::PHP;
    }

    #[Override]
    public function priority(): int
    {
        return 1;
    }

    #[Override]
    public function block(): string
    {
        return $this->block;
    }
}
