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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Skill;

use ArrayIterator;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\CustomAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Skill\AttackerSkillInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Skill\ConfiguredAttackerSkill;

final class AttackerSkillRegistryTest extends TestCase
{
    public function test_it_emits_only_the_blocks_for_present_file_types(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([
            $this->skill('voter', ProjectFileType::VOTER, 10),
            $this->skill('controller', ProjectFileType::CONTROLLER, 20),
        ]);

        $output = $attackerSkillRegistry->render([ProjectFileType::VOTER], emitAll: false);

        self::assertStringContainsString('<skills role="custom:voter">', $output);
        self::assertStringNotContainsString('<skills role="custom:controller">', $output);
    }

    public function test_emit_all_ignores_present_types_and_returns_every_block(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([
            $this->skill('voter', ProjectFileType::VOTER, 10),
            $this->skill('controller', ProjectFileType::CONTROLLER, 20),
        ]);

        $output = $attackerSkillRegistry->render([], emitAll: true);

        self::assertSame(2, substr_count($output, '<skills role="'));
    }

    public function test_it_emits_blocks_in_ascending_priority_order(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([
            $this->skill('last', ProjectFileType::VOTER, 30),
            $this->skill('first', ProjectFileType::VOTER, 10),
            $this->skill('middle', ProjectFileType::VOTER, 20),
        ]);

        $output = $attackerSkillRegistry->render([], emitAll: true);

        preg_match_all('/<skills role="([^"]+)">/', $output, $matches);

        self::assertSame(['custom:first', 'custom:middle', 'custom:last'], $matches[1]);
    }

    public function test_it_accepts_a_traversable_of_skills(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry(new ArrayIterator([
            $this->skill('second', ProjectFileType::VOTER, 20),
            $this->skill('first', ProjectFileType::VOTER, 10),
        ]));

        $output = $attackerSkillRegistry->render([], emitAll: true);

        preg_match_all('/<skills role="([^"]+)">/', $output, $matches);

        self::assertSame(['custom:first', 'custom:second'], $matches[1]);
    }

    public function test_it_returns_empty_string_when_no_skill_matches(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([$this->skill('voter', ProjectFileType::VOTER, 10)]);

        self::assertSame('', $attackerSkillRegistry->render([ProjectFileType::CONTROLLER], emitAll: false));
    }

    public function test_blocks_are_separated_by_a_blank_line(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([
            $this->skill('first', ProjectFileType::VOTER, 10),
            $this->skill('second', ProjectFileType::VOTER, 20),
        ]);

        $output = $attackerSkillRegistry->render([], emitAll: true);

        self::assertStringContainsString("</skills>\n\n<skills role=\"custom:second\">", $output);
    }

    private function skill(string $name, ProjectFileType $projectFileType, int $priority): AttackerSkillInterface
    {
        return new ConfiguredAttackerSkill(new CustomAttackerSkill(
            name: $name,
            fileType: $projectFileType,
            instructions: \sprintf('Inspect every %s.', $name),
            priority: $priority,
        ));
    }
}
