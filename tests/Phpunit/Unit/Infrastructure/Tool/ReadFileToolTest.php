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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\ReadFileTool;

final class ReadFileToolTest extends TestCase
{
    private const int MAX_BYTES = 64 * 1024;

    public function test_definition_matches_expected_full_schema(): void
    {
        $readFileTool = new ReadFileTool([]);

        $definition = $readFileTool->definition();

        self::assertSame('read_file', $definition->name);
        self::assertSame(
            [
                'type' => 'object',
                'properties' => [
                    'relative_path' => [
                        'type' => 'string',
                        'description' => 'Project-relative path, e.g. src/Controller/UserController.php',
                    ],
                ],
                'required' => ['relative_path'],
            ],
            $definition->parametersSchema,
        );
    }

    public function test_execute_returns_file_content_for_known_path(): void
    {
        $projectFile = ProjectFile::create('src/A.php', '/app/src/A.php', '<?php echo 1;');
        $readFileTool = new ReadFileTool([$projectFile]);

        $result = $readFileTool->execute(['relative_path' => 'src/A.php']);

        self::assertSame('<?php echo 1;', $result);
    }

    public function test_execute_returns_error_for_unknown_path(): void
    {
        $readFileTool = new ReadFileTool([]);

        $result = $readFileTool->execute(['relative_path' => 'src/nope.php']);

        self::assertStringContainsString('Error', $result);
        self::assertStringContainsString('src/nope.php', $result);
    }

    public function test_execute_returns_error_for_missing_argument(): void
    {
        $readFileTool = new ReadFileTool([]);

        $result = $readFileTool->execute([]);

        self::assertStringContainsString('Error', $result);
        self::assertStringContainsString('relative_path', $result);
    }

    public function test_execute_returns_error_for_non_string_argument(): void
    {
        $readFileTool = new ReadFileTool([]);

        $result = $readFileTool->execute(['relative_path' => 123]);

        self::assertStringContainsString('Error', $result);
    }

    public function test_execute_returns_error_for_empty_string_argument(): void
    {
        $readFileTool = new ReadFileTool([]);

        $result = $readFileTool->execute(['relative_path' => '']);

        self::assertStringContainsString('Error', $result);
    }

    public function test_execute_returns_full_content_when_exactly_at_size_limit(): void
    {
        // Boundary: `>` mutated to `>=` would truncate at exactly MAX_BYTES; original passes through.
        $content = str_repeat('a', self::MAX_BYTES);
        $projectFile = ProjectFile::create('src/Edge.php', '/app/src/Edge.php', $content);
        $readFileTool = new ReadFileTool([$projectFile]);

        self::assertSame($content, $readFileTool->execute(['relative_path' => 'src/Edge.php']));
    }

    public function test_execute_truncates_file_content_over_size_limit(): void
    {
        $largeContent = str_repeat('a', self::MAX_BYTES + 100);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $largeContent);
        $readFileTool = new ReadFileTool([$projectFile]);

        $result = $readFileTool->execute(['relative_path' => 'src/Big.php']);

        $expectedPrefix = str_repeat('a', self::MAX_BYTES);
        $expectedSuffix = "\n\n... [truncated to ".self::MAX_BYTES.' bytes]';

        self::assertStringStartsWith($expectedPrefix, $result);
        self::assertStringEndsWith($expectedSuffix, $result);
        self::assertSame(self::MAX_BYTES + \strlen($expectedSuffix), \strlen($result));
    }

    public function test_execute_truncation_preserves_original_leading_byte(): void
    {
        // Kills DecrementInteger / IncrementInteger on substr offset: truncated output must start
        // with the first byte of the original content.
        $content = 'Z'.str_repeat('a', self::MAX_BYTES + 10);
        $projectFile = ProjectFile::create('src/Big.php', '/app/src/Big.php', $content);
        $readFileTool = new ReadFileTool([$projectFile]);

        $result = $readFileTool->execute(['relative_path' => 'src/Big.php']);

        self::assertStringStartsWith('Z', $result);
    }

    public function test_execute_does_not_truncate_when_file_fits_in_limit(): void
    {
        $smallContent = str_repeat('x', 1024);
        $projectFile = ProjectFile::create('src/Small.php', '/app/src/Small.php', $smallContent);
        $readFileTool = new ReadFileTool([$projectFile]);

        $result = $readFileTool->execute(['relative_path' => 'src/Small.php']);

        self::assertSame($smallContent, $result);
    }
}
