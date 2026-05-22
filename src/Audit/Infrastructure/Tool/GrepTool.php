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
 * Case-sensitive substring search across the project files scanned by the
 * ingestion stage. Returns up to MAX_MATCHES matches as path:line lines.
 */
final readonly class GrepTool implements ToolInterface
{
    private const int MAX_MATCHES = 50;

    /**
     * @param list<ProjectFile> $files
     */
    public function __construct(private array $files) {}

    public function definition(): ToolDefinition
    {
        return new ToolDefinition(
            name: 'grep',
            description: 'Search project files for a literal substring (case-sensitive). Useful for finding all call sites of a method, all places a constant is referenced, or all controllers using a specific service.',
            parametersSchema: [
                'type' => 'object',
                'properties' => [
                    'pattern' => [
                        'type' => 'string',
                        'description' => 'Literal substring to search for.',
                    ],
                    'file_type' => [
                        'type' => 'string',
                        'description' => 'Optional ProjectFile::type() to restrict the search to: controller, voter, entity, repository, form, template, config, php.',
                    ],
                ],
                'required' => ['pattern'],
            ],
        );
    }

    public function execute(array $arguments): string
    {
        $pattern = $arguments['pattern'] ?? null;
        if (!\is_string($pattern) || '' === $pattern) {
            return 'Error: missing or empty "pattern" argument.';
        }

        $rawFileType = $arguments['file_type'] ?? null;
        $fileType = \is_string($rawFileType) && '' !== $rawFileType ? $rawFileType : null;

        $matches = [];
        foreach ($this->files as $file) {
            if (null !== $fileType && $file->type() !== $fileType) {
                continue;
            }

            $lines = explode("\n", $file->content());
            foreach ($lines as $lineIndex => $line) {
                if (str_contains($line, $pattern)) {
                    $matches[] = \sprintf('%s:%d:%s', $file->relativePath(), $lineIndex + 1, trim($line));
                    if (\count($matches) >= self::MAX_MATCHES) {
                        break 2;
                    }
                }
            }
        }

        if ([] === $matches) {
            return 'No matches found.';
        }

        return implode("\n", $matches);
    }
}
