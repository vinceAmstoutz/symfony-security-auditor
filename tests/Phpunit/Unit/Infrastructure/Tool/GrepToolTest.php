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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\GrepTool;

final class GrepToolTest extends TestCase
{
    private const int MAX_MATCHES = 50;

    /**
     * @throws InvalidToolDefinitionException
     */
    public function test_definition_matches_expected_full_schema(): void
    {
        $grepTool = new GrepTool([]);

        $definition = $grepTool->definition();

        self::assertSame('grep', $definition->name);
        self::assertSame(
            [
                'type' => 'object',
                'properties' => [
                    'pattern' => [
                        'type' => 'string',
                        'description' => 'Literal substring to search for.',
                    ],
                    'file_type' => [
                        'type' => 'string',
                        'description' => 'Optional ProjectFile::type() to restrict the search to: controller, api_resource, live_component, entity, voter, repository, form, authenticator, ldap_service, sonata_admin, easyadmin_crud, messenger_handler, webhook_consumer, event_subscriber, normalizer, scheduler, twig_extension, template, config, php, other.',
                    ],
                ],
                'required' => ['pattern'],
            ],
            $definition->parametersSchema,
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_returns_no_matches_message_when_pattern_not_found(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', "line1\nline2\n");
        $grepTool = new GrepTool([$projectFile]);

        $result = $grepTool->execute(['pattern' => 'banana']);

        self::assertSame('No matches found.', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_returns_path_line_number_and_trimmed_content_for_each_match(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', "first\n  foo bar  \nthird\nfoo baz\n");
        $grepTool = new GrepTool([$projectFile]);

        $result = $grepTool->execute(['pattern' => 'foo']);

        self::assertSame(
            "src/A.php:2:foo bar\nsrc/A.php:4:foo baz",
            $result,
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_filters_by_file_type_when_specified(): void
    {
        $projectFile = ProjectFile::create('src/Controller/AController.php', '/app/x', 'echo foo;');
        $entity = ProjectFile::create('src/Entity/User.php', '/app/y', 'echo foo;');

        $grepTool = new GrepTool([$projectFile, $entity]);

        $result = $grepTool->execute(['pattern' => 'foo', 'file_type' => 'controller']);

        self::assertStringContainsString('src/Controller/AController.php', $result);
        self::assertStringNotContainsString('src/Entity/User.php', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_continues_past_filtered_files_to_reach_matching_ones(): void
    {
        // Kills Continue_→break mutation: with `break`, the non-matching first file would stop iteration
        // and the second file's matches would never be reported.
        $projectFile = ProjectFile::create('src/Entity/User.php', '/app/y', 'echo foo;');
        $controllerSecond = ProjectFile::create('src/Controller/AController.php', '/app/x', 'echo foo;');

        $grepTool = new GrepTool([$projectFile, $controllerSecond]);

        $result = $grepTool->execute(['pattern' => 'foo', 'file_type' => 'controller']);

        self::assertStringContainsString('src/Controller/AController.php', $result);
        self::assertStringNotContainsString('src/Entity/User.php', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_ignores_invalid_file_type_filter(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/x', 'echo foo;');
        $grepTool = new GrepTool([$projectFile]);

        $result = $grepTool->execute(['pattern' => 'foo', 'file_type' => 'nonexistent']);

        self::assertStringContainsString('No matches found', $result);
    }

    public function test_execute_returns_error_for_missing_pattern(): void
    {
        $grepTool = new GrepTool([]);

        $result = $grepTool->execute([]);

        self::assertStringContainsString('Error', $result);
        self::assertStringContainsString('pattern', $result);
    }

    public function test_execute_returns_error_for_empty_pattern(): void
    {
        $grepTool = new GrepTool([]);

        $result = $grepTool->execute(['pattern' => '']);

        self::assertStringContainsString('Error', $result);
    }

    public function test_execute_returns_error_for_non_string_pattern(): void
    {
        $grepTool = new GrepTool([]);

        $result = $grepTool->execute(['pattern' => 123]);

        self::assertStringContainsString('Error', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_caps_results_at_max_matches_keeping_earliest_matches_across_files(): void
    {
        $contentA = '';
        $contentB = '';
        for ($i = 0; $i < 30; ++$i) {
            $contentA .= "foo a\n";
            $contentB .= "foo b\n";
        }

        $projectFile = ProjectFile::create('src/A.php', '/app/A', $contentA);
        $fileB = ProjectFile::create('src/B.php', '/app/B', $contentB);

        $grepTool = new GrepTool([$projectFile, $fileB]);

        $result = $grepTool->execute(['pattern' => 'foo']);

        // 30 from the first file are all kept; the second file fills the cap to 50.
        self::assertSame(30, substr_count($result, 'src/A.php'));
        self::assertSame(self::MAX_MATCHES - 30, substr_count($result, 'src/B.php'));
        self::assertStringContainsString('src/A.php:1:', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_truncates_a_single_excessively_long_matching_line(): void
    {
        $hugeLine = str_repeat('A', 20_000).'NEEDLE';
        $projectFile = ProjectFile::create('src/Huge.php', '/app/Huge', "header\n{$hugeLine}\nfooter\n");

        $grepTool = new GrepTool([$projectFile]);

        $result = $grepTool->execute(['pattern' => 'NEEDLE']);

        self::assertLessThan(1000, \strlen($result));
        self::assertStringContainsString('[truncated]', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_treats_empty_file_type_as_unset(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/x', 'foo bar');
        $grepTool = new GrepTool([$projectFile]);

        $result = $grepTool->execute(['pattern' => 'foo', 'file_type' => '']);

        self::assertStringContainsString('src/A.php', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_returns_a_line_at_exactly_the_length_limit_untruncated(): void
    {
        $line = 'NEEDLE'.str_repeat('a', 494); // exactly 500 chars
        $projectFile = ProjectFile::create('src/Bound.php', '/app/Bound', $line."\n");
        $grepTool = new GrepTool([$projectFile]);

        $result = $grepTool->execute(['pattern' => 'NEEDLE']);

        self::assertSame('src/Bound.php:1:'.$line, $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_truncates_from_the_start_of_an_overlong_line(): void
    {
        $line = 'Z'.str_repeat('y', 600); // 601 chars, distinct first char
        $projectFile = ProjectFile::create('src/Off.php', '/app/Off', $line."\n");
        $grepTool = new GrepTool([$projectFile]);

        $result = $grepTool->execute(['pattern' => 'Z']);

        self::assertSame('src/Off.php:1:Z'.str_repeat('y', 499).'... [truncated]', $result);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_execute_truncates_on_a_character_boundary_not_a_byte_boundary(): void
    {
        // Byte 500 falls inside the 3-byte '€'; a byte-wise cut would emit a
        // broken half-character, a character-safe cut stops before it.
        $line = str_repeat('a', 499).'€NEEDLE'; // 508 bytes, match past the cut
        $projectFile = ProjectFile::create('src/Mb.php', '/app/Mb', $line."\n");
        $grepTool = new GrepTool([$projectFile]);

        $result = $grepTool->execute(['pattern' => 'NEEDLE']);

        self::assertSame('src/Mb.php:1:'.str_repeat('a', 499).'... [truncated]', $result);
    }
}
