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

use function Symfony\Component\String\u;

/**
 * Case-sensitive substring search across the project files scanned by the
 * ingestion stage. Returns up to MAX_MATCHES matches as path:line lines.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GrepTool implements ToolInterface
{
    private const int MAX_MATCHES = 50;

    private const int MAX_LINE_LENGTH = 500;

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

    #[Override]
    public function execute(array $arguments): string
    {
        $pattern = $arguments['pattern'] ?? null;
        if (!\is_string($pattern) || '' === $pattern) {
            return 'Error: missing or empty "pattern" argument.';
        }

        $matches = $this->collectMatches($pattern, $this->resolveFileType($arguments));

        if ([] === $matches) {
            return 'No matches found.';
        }

        return implode("\n", $matches);
    }

    /**
     * @param array<string, mixed> $arguments
     */
    private function resolveFileType(array $arguments): ?string
    {
        $rawFileType = $arguments['file_type'] ?? null;

        return \is_string($rawFileType) && '' !== $rawFileType ? $rawFileType : null;
    }

    /**
     * @return list<string>
     */
    private function collectMatches(string $pattern, ?string $fileType): array
    {
        $matches = [];
        foreach ($this->files as $file) {
            if (null !== $fileType && $file->type() !== $fileType) {
                continue;
            }

            $matches = $this->appendUpToCap($matches, $this->matchesInFile($file, $pattern));
        }

        return $matches;
    }

    /**
     * @param list<string>     $matches
     * @param iterable<string> $newMatches
     *
     * @return list<string>
     */
    private function appendUpToCap(array $matches, iterable $newMatches): array
    {
        foreach ($newMatches as $newMatch) {
            if (\count($matches) >= self::MAX_MATCHES) {
                return $matches;
            }

            $matches[] = $newMatch;
        }

        return $matches;
    }

    /**
     * @return iterable<string>
     */
    private function matchesInFile(ProjectFile $projectFile, string $pattern): iterable
    {
        $lines = explode("\n", $projectFile->content());
        foreach ($lines as $lineIndex => $line) {
            if (!u($line)->containsAny($pattern)) {
                continue;
            }

            yield \sprintf('%s:%d:%s', $projectFile->relativePath(), $lineIndex + 1, $this->truncateLine(u($line)->trim()->toString()));
        }
    }

    /**
     * A single matched line's length is otherwise unbounded — audited-project
     * content fully controls it (e.g. a long inline base64/SVG blob or config
     * value), and unlike {@see MAX_MATCHES}, capping the match count alone
     * does nothing to bound a single oversized line sent to the LLM.
     */
    private function truncateLine(string $line): string
    {
        if (\strlen($line) <= self::MAX_LINE_LENGTH) {
            return $line;
        }

        return \sprintf('%s... [truncated]', mb_strcut($line, 0, self::MAX_LINE_LENGTH, 'UTF-8'));
    }
}
