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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\UnreadableYamlException;

/**
 * The files of the scan a YAML configuration file imports: the `resource` of
 * each `imports` entry, read relative to the importing file, with at most one
 * `*` in the file name. Only files the scan already holds can match, so an
 * import never reaches outside the project and nothing is read from the
 * disk; each import looks among the files of the one folder it names.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class YamlImportResolver
{
    private const string PRODUCTION_ENVIRONMENT_BLOCK = 'when@prod';

    private const int MAX_IMPORTS_PER_FILE = 32;

    /**
     * @param array<mixed>                        $document the importing file, parsed
     * @param callable(string): list<ProjectFile> $filesIn  the YAML files the scan holds directly in a folder, in path order
     *
     * @return list<ProjectFile>
     *
     * @throws UnreadableYamlException when the file imports more resources than the audit follows
     */
    public function importedFiles(ProjectFile $projectFile, array $document, callable $filesIn): array
    {
        $resources = $this->resourcesOf($document);
        if (self::MAX_IMPORTS_PER_FILE < \count($resources)) {
            throw UnreadableYamlException::tooManyImports(\count($resources), self::MAX_IMPORTS_PER_FILE);
        }

        $folder = Path::getDirectory($projectFile->relativePath());
        $imported = [];
        foreach ($resources as $resource) {
            if (!Path::isAbsolute($resource)) {
                $imported = [...$imported, ...$this->filesNamedBy(Path::join($folder, $resource), $filesIn)];
            }
        }

        return $imported;
    }

    /**
     * @param callable(string): list<ProjectFile> $filesIn
     *
     * @return array<int, ProjectFile>
     */
    private function filesNamedBy(string $path, callable $filesIn): array
    {
        $pattern = basename($path);

        return array_filter(
            $filesIn(Path::getDirectory($path)),
            static fn (ProjectFile $projectFile): bool => self::nameMatches($pattern, basename($projectFile->relativePath())),
        );
    }

    /**
     * One `*` is read as a wildcard, so matching stays linear in the length
     * of the name whatever the repository writes.
     */
    private static function nameMatches(string $pattern, string $name): bool
    {
        $parts = explode('*', $pattern);

        return match (\count($parts)) {
            1 => $pattern === $name,
            2 => \strlen($parts[0]) + \strlen($parts[1]) <= \strlen($name) && str_starts_with($name, $parts[0]) && str_ends_with($name, $parts[1]),
            default => false,
        };
    }

    /**
     * The production kernel reads the imports of the root block, then those
     * of the `when@prod` block; a `when@test` or `when@dev` block imports
     * nothing in production.
     *
     * @param array<mixed> $document
     *
     * @return list<string>
     */
    private function resourcesOf(array $document): array
    {
        $productionBlock = $this->blockOf($document[self::PRODUCTION_ENVIRONMENT_BLOCK] ?? null);

        return [...$this->importResources($document['imports'] ?? null), ...$this->importResources($productionBlock['imports'] ?? null)];
    }

    /**
     * @return list<string>
     */
    private function importResources(mixed $imports): array
    {
        return array_values(array_filter(array_map($this->resourceOf(...), $this->blockOf($imports)), \is_string(...)));
    }

    /**
     * An import is either the resource itself or a map holding it under `resource`.
     */
    private function resourceOf(mixed $import): mixed
    {
        return \is_array($import) ? ($import['resource'] ?? null) : $import;
    }

    /**
     * @return array<mixed>
     */
    private function blockOf(mixed $value): array
    {
        return \is_array($value) ? $value : [];
    }
}
