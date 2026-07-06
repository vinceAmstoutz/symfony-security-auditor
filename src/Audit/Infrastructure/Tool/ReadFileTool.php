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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolDefinitionException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Returns the textual content of a project file by its relative path. The set
 * of readable files is fixed at construction time to the project files scanned
 * by IngestionStage — the LLM cannot escape outside the audited project tree.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReadFileTool implements ToolInterface
{
    private const int MAX_BYTES = 64 * 1024;

    /**
     * @var array<string, ProjectFile>
     */
    private array $filesByPath;

    /**
     * @param list<ProjectFile> $files
     */
    public function __construct(array $files)
    {
        $byPath = [];
        foreach ($files as $file) {
            $byPath[$file->relativePath()] = $file;
        }

        $this->filesByPath = $byPath;
    }

    /**
     * @throws InvalidToolDefinitionException
     */
    #[Override]
    public function definition(): ToolDefinition
    {
        return new ToolDefinition(
            name: 'read_file',
            description: 'Read the textual content of a file from the audited project, by its project-relative path. Use this to follow cross-file flows that the chunked source listing does not show in full.',
            parametersSchema: [
                'type' => 'object',
                'properties' => [
                    'relative_path' => [
                        'type' => 'string',
                        'description' => 'Project-relative path, e.g. src/Controller/UserController.php',
                    ],
                ],
                'required' => ['relative_path'],
            ],
        );
    }

    #[Override]
    public function execute(array $arguments): string
    {
        $rawPath = $arguments['relative_path'] ?? null;

        if (!\is_string($rawPath) || '' === $rawPath) {
            return 'Error: missing or empty "relative_path" argument.';
        }

        if (!\array_key_exists($rawPath, $this->filesByPath)) {
            return \sprintf('Error: file "%s" is not part of the audited project.', $rawPath);
        }

        $content = $this->filesByPath[$rawPath]->content();

        if (\strlen($content) > self::MAX_BYTES) {
            return \sprintf("%s\n\n... [truncated to %d bytes]", substr($content, 0, self::MAX_BYTES), self::MAX_BYTES);
        }

        return $content;
    }
}
