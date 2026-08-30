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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking;

use Symfony\Component\String\UnicodeString;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ChunkingVocabulary;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class FileChunker
{
    private const int DEFAULT_CHUNK_SIZE = 10;

    /** @var int<1, max> */
    private int $chunkSize;

    public function __construct(
        private ChunkingStrategy $chunkingStrategy = ChunkingStrategy::Feature,
        int $chunkSize = self::DEFAULT_CHUNK_SIZE,
        private ChunkingVocabulary $chunkingVocabulary = new ChunkingVocabulary(),
    ) {
        $this->chunkSize = max(1, $chunkSize);
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<list<ProjectFile>>
     */
    public function chunk(array $files): array
    {
        return match ($this->chunkingStrategy) {
            ChunkingStrategy::Feature => $this->chunkByFeature($files),
            ChunkingStrategy::Type => $this->chunkByType($files),
        };
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<list<ProjectFile>>
     */
    private function chunkByType(array $files): array
    {
        return $this->prioritizedChunks($files);
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<list<ProjectFile>>
     */
    private function chunkByFeature(array $files): array
    {
        $featureNames = $this->extractFeatureNames($files);
        $assignments = $this->assignFilesToFeatures($files, $featureNames);

        $chunks = [];
        $assignedPaths = [];

        foreach ($featureNames as $featureName) {
            $featureFiles = $assignments[$featureName] ?? [];

            if ([] === $featureFiles) {
                continue;
            }

            $chunks = [...$chunks, ...$this->prioritizedChunks($featureFiles)];
            $assignedPaths = $this->markAssigned($featureFiles, $assignedPaths);
        }

        return [...$chunks, ...$this->prioritizedChunks($this->leftovers($files, $assignedPaths))];
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<list<ProjectFile>>
     */
    private function prioritizedChunks(array $files): array
    {
        usort($files, fn (ProjectFile $a, ProjectFile $b): int => $this->priority($a) <=> $this->priority($b));

        return array_chunk($files, $this->chunkSize);
    }

    /**
     * @param list<ProjectFile>   $featureFiles
     * @param array<string, true> $assignedPaths
     *
     * @return array<string, true>
     */
    private function markAssigned(array $featureFiles, array $assignedPaths): array
    {
        foreach ($featureFiles as $featureFile) {
            $assignedPaths[$featureFile->relativePath()] = true;
        }

        return $assignedPaths;
    }

    /**
     * @param list<ProjectFile>   $files
     * @param array<string, true> $assignedPaths
     *
     * @return list<ProjectFile>
     */
    private function leftovers(array $files, array $assignedPaths): array
    {
        return array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => !\array_key_exists($projectFile->relativePath(), $assignedPaths),
        ));
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<string>
     */
    private function extractFeatureNames(array $files): array
    {
        $names = [];
        foreach ($files as $file) {
            if (!$file->fileType()->isControllerLike()) {
                continue;
            }

            $featureName = $this->featureNameOf($file);

            if (null !== $featureName) {
                $names[] = $featureName;
            }
        }

        return array_values(array_unique($names));
    }

    private function featureNameOf(ProjectFile $projectFile): ?string
    {
        $featureName = $this->chunkingVocabulary->featureNameOf(
            $projectFile->fileType(),
            basename($projectFile->relativePath(), '.php'),
        );

        return '' === $featureName ? null : $featureName;
    }

    /**
     * @param list<ProjectFile> $files
     * @param list<string>      $featureNames
     *
     * @return array<string, list<ProjectFile>>
     */
    private function assignFilesToFeatures(array $files, array $featureNames): array
    {
        $assignments = [];

        foreach ($featureNames as $featureName) {
            $assignments[$featureName] = [];
        }

        foreach ($files as $file) {
            $matchedFeature = $this->findFeatureForFile($file, $featureNames);

            if (null === $matchedFeature) {
                continue;
            }

            $assignments[$matchedFeature][] = $file;
        }

        return $assignments;
    }

    /**
     * @param list<string> $featureNames
     */
    private function findFeatureForFile(ProjectFile $projectFile, array $featureNames): ?string
    {
        $baseName = $this->chunkingVocabulary->stripTemplateExtension(basename($projectFile->relativePath(), '.php'));
        $relativePath = $projectFile->relativePath();

        $matchedFeature = null;
        foreach ($featureNames as $featureName) {
            if (!$this->fileBelongsToFeature($baseName, $relativePath, $featureName)) {
                continue;
            }

            if (null === $matchedFeature || \strlen($featureName) > \strlen($matchedFeature)) {
                $matchedFeature = $featureName;
            }
        }

        return $matchedFeature;
    }

    private function fileBelongsToFeature(string $baseName, string $relativePath, string $featureName): bool
    {
        if ($this->baseNameStartsAtFeatureBoundary($baseName, $featureName)) {
            return true;
        }

        return u($relativePath)->ignoreCase()->containsAny(\sprintf('/%s/', $featureName));
    }

    /**
     * `startsWith()` alone would let `UsersController` match feature `User` —
     * the prefix stops mid-word instead of at a CamelCase boundary. Requiring
     * the remainder to be empty or start with an uppercase letter rejects that
     * false match while still matching `UserController`, `UserRepository`, ….
     */
    private function baseNameStartsAtFeatureBoundary(string $baseName, string $featureName): bool
    {
        if (!u($baseName)->startsWith($featureName)) {
            return false;
        }

        $remainder = u($baseName)->slice(u($featureName)->length());
        if (0 === $remainder->length()) {
            return true;
        }

        return $this->isUppercaseLetter($remainder->slice(0, 1));
    }

    private function isUppercaseLetter(UnicodeString $unicodeString): bool
    {
        return $unicodeString->upper()->equalsTo($unicodeString) && !$unicodeString->lower()->equalsTo($unicodeString);
    }

    private function priority(ProjectFile $projectFile): int
    {
        return $this->chunkingVocabulary->priorityOf($projectFile->fileType());
    }
}
