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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Lists project files, optionally filtered by ProjectFile::type(). Lets the
 * attacker survey the project topology without consuming context for the actual
 * file contents.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ListFilesTool implements ToolInterface
{
    private const int MAX_FILES = 2000;

    /**
     * @param list<ProjectFile> $files
     */
    public function __construct(private array $files) {}

    /**
     * @throws InvalidToolDefinitionException
     */
    #[Override]
    public function definition(): ToolDefinition
    {
        return new ToolDefinition(
            name: 'list_files',
            description: 'List all files in the audited project, optionally filtered by type. Each line is "path [type]". Useful for surveying the project before drilling into specific files.',
            parametersSchema: [
                'type' => 'object',
                'properties' => [
                    'file_type' => [
                        'type' => 'string',
                        'description' => \sprintf('Optional ProjectFile::type() to filter by: %s.', $this->fileTypeValues()),
                    ],
                ],
            ],
        );
    }

    private function fileTypeValues(): string
    {
        return implode(', ', array_map(
            static fn (ProjectFileType $projectFileType): string => $projectFileType->value,
            ProjectFileType::cases(),
        ));
    }

    #[Override]
    public function execute(array $arguments): string
    {
        $rawFileType = $arguments['file_type'] ?? null;
        $fileType = \is_string($rawFileType) && '' !== $rawFileType ? $rawFileType : null;

        $matched = [];
        foreach ($this->files as $file) {
            if (null !== $fileType && $file->type() !== $fileType) {
                continue;
            }

            $matched[] = $file;
        }

        if ([] === $matched) {
            return 'No files match.';
        }

        return $this->render($matched);
    }

    /**
     * `ProjectFileScanner` bounds an individual file's size but never the
     * total number of scanned files, so an unfiltered listing on a large
     * project (or one deliberately padded with many small stub files) could
     * otherwise blow the token budget with no mitigation, unlike this tool's
     * siblings ({@see ReadFileTool}, {@see GrepTool}).
     *
     * @param list<ProjectFile> $matched
     */
    private function render(array $matched): string
    {
        $shown = \array_slice($matched, 0, self::MAX_FILES);
        $lines = array_map(
            static fn (ProjectFile $projectFile): string => \sprintf('%s [%s]', $projectFile->relativePath(), $projectFile->type()),
            $shown,
        );

        $omitted = \count($matched) - \count($shown);
        if ($omitted > 0) {
            $lines[] = \sprintf('... [truncated: %d more files not shown, narrow with "file_type"]', $omitted);
        }

        return implode("\n", $lines);
    }
}
