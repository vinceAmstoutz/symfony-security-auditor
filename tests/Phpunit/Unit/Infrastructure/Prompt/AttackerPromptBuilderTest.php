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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;

final class AttackerPromptBuilderTest extends TestCase
{
    private AttackerPromptBuilder $attackerPromptBuilder;

    protected function setUp(): void
    {
        $this->attackerPromptBuilder = new AttackerPromptBuilder();
    }

    public function test_it_formats_no_voter_controller_list_with_prefix_and_path(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/PublicController.php',
            '/app/src/Controller/PublicController.php',
            '<?php class PublicController {}',
        );

        $symfonyMapping = SymfonyMapping::create(controllers: [$projectFile]);

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile], $symfonyMapping);

        self::assertStringContainsString('  - src/Controller/PublicController.php', $message);
    }

    public function test_it_excludes_secured_controllers_from_no_voter_list(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/SecuredController.php',
            '/app/src/Controller/SecuredController.php',
            '<?php class SecuredController { public function __construct() { $this->denyAccessUnlessGranted("ROLE_USER"); } }',
        );

        $symfonyMapping = SymfonyMapping::create(controllers: [$projectFile]);

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile], $symfonyMapping);

        self::assertStringNotContainsString('  - src/Controller/SecuredController.php', $message);
    }

    public function test_it_lists_multiple_no_voter_controllers_each_on_own_line(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/AController.php',
            '/app/src/Controller/AController.php',
            '<?php class AController {}',
        );
        $controllerB = ProjectFile::create(
            'src/Controller/BController.php',
            '/app/src/Controller/BController.php',
            '<?php class BController {}',
        );

        $symfonyMapping = SymfonyMapping::create(controllers: [$projectFile, $controllerB]);

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile, $controllerB], $symfonyMapping);

        self::assertStringContainsString('  - src/Controller/AController.php', $message);
        self::assertStringContainsString('  - src/Controller/BController.php', $message);
    }

    public function test_base_system_prompt_has_no_specialist_skill_block_when_no_files(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('elite offensive security researcher', $prompt);
        self::assertStringNotContainsString('Specialist Skills', $prompt);
    }

    public function test_it_injects_controller_skills_when_controller_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Controller Specialist Skills', $prompt);
        self::assertStringContainsString('denyAccessUnlessGranted', $prompt);
        self::assertStringNotContainsString('Voter Specialist Skills', $prompt);
    }

    public function test_it_injects_voter_skills_when_voter_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/PostVoter.php',
            '/app/src/Security/PostVoter.php',
            '<?php class PostVoter {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Voter Specialist Skills', $prompt);
        self::assertStringContainsString('voteOnAttribute', $prompt);
    }

    public function test_it_injects_entity_skills_when_entity_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/User.php',
            '/app/src/Entity/User.php',
            '<?php namespace App\\Entity; class User {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Entity / Doctrine Specialist Skills', $prompt);
    }

    public function test_it_injects_repository_skills_when_repository_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Repository/UserRepository.php',
            '/app/src/Repository/UserRepository.php',
            '<?php class UserRepository {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Repository Specialist Skills', $prompt);
    }

    public function test_it_injects_form_skills_when_form_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Form/UserType.php',
            '/app/src/Form/UserType.php',
            '<?php class UserType {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Form Specialist Skills', $prompt);
    }

    public function test_it_injects_template_skills_when_twig_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'templates/base.html.twig',
            '/app/templates/base.html.twig',
            '{{ user.name }}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Twig Template Specialist Skills', $prompt);
    }

    public function test_it_injects_config_skills_when_yaml_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'config/packages/security.yaml',
            '/app/config/packages/security.yaml',
            'security: {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Configuration Specialist Skills', $prompt);
    }

    public function test_it_injects_php_skills_when_generic_service_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Mailer.php',
            '/app/src/Service/Mailer.php',
            '<?php class Mailer {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Generic PHP Service Specialist Skills', $prompt);
    }

    public function test_it_combines_multiple_skill_blocks_when_chunk_has_mixed_types(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );
        $voter = ProjectFile::create(
            'src/Security/PostVoter.php',
            '/app/src/Security/PostVoter.php',
            '<?php class PostVoter {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile, $voter]);

        self::assertStringContainsString('Controller Specialist Skills', $prompt);
        self::assertStringContainsString('Voter Specialist Skills', $prompt);
    }

    public function test_skill_blocks_are_emitted_in_sorted_order_when_multiple_types(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/PostVoter.php',
            '/app/src/Security/PostVoter.php',
            '<?php class PostVoter {}',
        );
        $controller = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile, $controller]);

        // 'controller' < 'voter' alphabetically — controller block must appear first regardless of input order
        $controllerPos = strpos($prompt, 'Controller Specialist Skills');
        $voterPos = strpos($prompt, 'Voter Specialist Skills');

        self::assertNotFalse($controllerPos);
        self::assertNotFalse($voterPos);
        self::assertLessThan($voterPos, $controllerPos);
    }

    public function test_each_type_skill_block_appears_only_once_when_chunk_has_duplicates(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/AController.php',
            '/app/src/Controller/AController.php',
            '<?php class AController {}',
        );
        $controllerB = ProjectFile::create(
            'src/Controller/BController.php',
            '/app/src/Controller/BController.php',
            '<?php class BController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile, $controllerB]);

        self::assertSame(1, substr_count($prompt, 'Controller Specialist Skills'));
    }

    public function test_unknown_file_type_does_not_inject_skill_block(): void
    {
        $projectFile = ProjectFile::create(
            'unknown.bin',
            '/app/unknown.bin',
            'binary',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringNotContainsString('Specialist Skills', $prompt);
    }

    public function test_base_prompt_has_no_trailing_separator_when_no_files(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringEndsWith('Return ONLY the JSON array, no prose, no markdown fences', $prompt);
    }

    public function test_base_prompt_has_no_trailing_separator_when_files_have_no_matching_skill(): void
    {
        $projectFile = ProjectFile::create(
            'unknown.bin',
            '/app/unknown.bin',
            'binary',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringEndsWith('Return ONLY the JSON array, no prose, no markdown fences', $prompt);
    }

    public function test_skill_block_is_separated_from_base_by_exactly_one_blank_line(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString(
            "Return ONLY the JSON array, no prose, no markdown fences\n\n### Controller Specialist Skills",
            $prompt,
        );
    }

    public function test_prompt_starts_with_base_persona_even_when_skills_present(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringStartsWith('You are an elite offensive security researcher', $prompt);
    }
}
