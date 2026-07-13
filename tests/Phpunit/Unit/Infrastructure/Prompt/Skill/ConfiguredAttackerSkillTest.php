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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt\Skill;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\CustomAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfiguredAttackerSkill;

final class ConfiguredAttackerSkillTest extends TestCase
{
    public function test_it_exposes_the_configured_file_type(): void
    {
        self::assertSame(ProjectFileType::REPOSITORY, $this->skill(ProjectFileType::REPOSITORY)->fileType());
    }

    public function test_it_exposes_the_configured_priority(): void
    {
        self::assertSame(500, $this->skill()->priority());
    }

    public function test_it_wraps_the_instructions_in_a_custom_named_skill_block(): void
    {
        $configuredAttackerSkill = $this->skill(ProjectFileType::REPOSITORY, 'legacy-db', 'All queries must go through SafeQuery.');

        self::assertSame(
            "<skills role=\"custom:legacy-db\">\nAll queries must go through SafeQuery.\n</skills>",
            $configuredAttackerSkill->block(),
        );
    }

    public function test_a_multi_word_skill_name_is_collapsed_to_a_single_line_role(): void
    {
        $configuredAttackerSkill = $this->skill(ProjectFileType::PHP, "legacy   db\naudit", 'x');

        self::assertStringContainsString('role="custom:legacy db audit"', $configuredAttackerSkill->block());
    }

    public function test_surrounding_whitespace_is_trimmed_from_the_instructions(): void
    {
        $configuredAttackerSkill = $this->skill(ProjectFileType::PHP, 'n', "\n  hunt this  \n");

        self::assertStringContainsString("\nhunt this\n", $configuredAttackerSkill->block());
    }

    private function skill(ProjectFileType $projectFileType = ProjectFileType::PHP, string $name = 'n', string $instructions = 'i'): ConfiguredAttackerSkill
    {
        return new ConfiguredAttackerSkill(new CustomAttackerSkill($name, $projectFileType, $instructions, 500));
    }
}
