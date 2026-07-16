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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Tool;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\ListFilesTool;

final class ListFilesToolTest extends TestCase
{
    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_definition_matches_expected_full_schema(): void
    {
        $listFilesTool = new ListFilesTool([]);

        $definition = $listFilesTool->definition();

        self::assertSame('list_files', $definition->name);
        self::assertSame(
            [
                'type' => 'object',
                'properties' => [
                    'file_type' => [
                        'type' => 'string',
                        'description' => 'Optional ProjectFile::type() to filter by: controller, api_resource, live_component, entity, voter, repository, form, authenticator, ldap_service, admin_panel, messenger_handler, webhook_consumer, event_subscriber, normalizer, scheduler, twig_extension, template, config, php, other.',
                    ],
                ],
            ],
            $definition->parametersSchema,
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_lists_all_files_when_no_filter(): void
    {
        $projectFile = ProjectFile::create('src/Controller/AController.php', '/app/x', '<?php');
        $entity = ProjectFile::create('src/Entity/Foo.php', '/app/y', '<?php');
        $listFilesTool = new ListFilesTool([$projectFile, $entity]);

        $result = $listFilesTool->execute([]);

        self::assertSame(
            "src/Controller/AController.php [controller]\nsrc/Entity/Foo.php [entity]",
            $result,
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_filters_by_file_type_when_specified(): void
    {
        $projectFile = ProjectFile::create('src/Controller/AController.php', '/app/x', '<?php');
        $entity = ProjectFile::create('src/Entity/Foo.php', '/app/y', '<?php');
        $listFilesTool = new ListFilesTool([$projectFile, $entity]);

        $result = $listFilesTool->execute(['file_type' => 'controller']);

        self::assertStringContainsString('src/Controller/AController.php', $result);
        self::assertStringNotContainsString('src/Entity/Foo.php', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_continues_past_filtered_files_to_reach_matching_ones(): void
    {
        // Kills Continue_→break: with `break`, iteration stops at first non-matching file and the
        // matching one further down the list never appears in output.
        $projectFile = ProjectFile::create('src/Entity/Foo.php', '/app/y', '<?php');
        $controller = ProjectFile::create('src/Controller/AController.php', '/app/x', '<?php');
        $listFilesTool = new ListFilesTool([$projectFile, $controller]);

        $result = $listFilesTool->execute(['file_type' => 'controller']);

        self::assertStringContainsString('src/Controller/AController.php', $result);
        self::assertStringNotContainsString('src/Entity/Foo.php', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_returns_no_files_match_when_filter_excludes_all(): void
    {
        $projectFile = ProjectFile::create('src/Controller/AController.php', '/app/x', '<?php');
        $listFilesTool = new ListFilesTool([$projectFile]);

        $result = $listFilesTool->execute(['file_type' => 'voter']);

        self::assertSame('No files match.', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_treats_empty_file_type_as_unset(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/x', '<?php');
        $listFilesTool = new ListFilesTool([$projectFile]);

        $result = $listFilesTool->execute(['file_type' => '']);

        self::assertStringContainsString('src/A.php', $result);
    }

    public function test_execute_returns_no_files_match_when_files_list_is_empty(): void
    {
        $listFilesTool = new ListFilesTool([]);

        $result = $listFilesTool->execute([]);

        self::assertSame('No files match.', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_caps_output_at_max_files_and_notes_how_many_were_omitted(): void
    {
        $files = [];
        for ($i = 0; $i < 2500; ++$i) {
            $files[] = ProjectFile::create(\sprintf('src/Generated/File%d.php', $i), '/app/x'.$i, '<?php');
        }

        $listFilesTool = new ListFilesTool($files);

        $result = $listFilesTool->execute([]);

        self::assertSame(2000, substr_count($result, '.php ['));
        self::assertStringContainsString('500 more files', $result);
    }
}
