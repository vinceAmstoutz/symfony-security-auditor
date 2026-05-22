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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;

/**
 * Lists project files, optionally filtered by ProjectFile::type(). Lets the
 * attacker survey the project topology without consuming context for the actual
 * file contents.
 */
final readonly class ListFilesTool implements ToolInterface
{
    /**
     * @param list<ProjectFile> $files
     */
    public function __construct(private array $files) {}

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
                        'description' => 'Optional ProjectFile::type() to filter by: controller, voter, entity, repository, form, template, config, php.',
                    ],
                ],
            ],
        );
    }

    public function execute(array $arguments): string
    {
        $rawFileType = $arguments['file_type'] ?? null;
        $fileType = \is_string($rawFileType) && '' !== $rawFileType ? $rawFileType : null;

        $lines = [];
        foreach ($this->files as $file) {
            if (null !== $fileType && $file->type() !== $fileType) {
                continue;
            }

            $lines[] = \sprintf('%s [%s]', $file->relativePath(), $file->type());
        }

        if ([] === $lines) {
            return 'No files match.';
        }

        return implode("\n", $lines);
    }
}
