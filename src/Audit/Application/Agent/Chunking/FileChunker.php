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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class FileChunker
{
    private const int DEFAULT_CHUNK_SIZE = 10;

    /**
     * @var list<ProjectFileType>
     */
    private const array TYPE_PRIORITY = [
        ProjectFileType::CONTROLLER,
        ProjectFileType::API_RESOURCE,
        ProjectFileType::LIVE_COMPONENT,
        ProjectFileType::AUTHENTICATOR,
        ProjectFileType::VOTER,
        ProjectFileType::WEBHOOK_CONSUMER,
        ProjectFileType::MESSENGER_HANDLER,
        ProjectFileType::EVENT_SUBSCRIBER,
        ProjectFileType::NORMALIZER,
        ProjectFileType::ENTITY,
        ProjectFileType::REPOSITORY,
        ProjectFileType::FORM,
        ProjectFileType::SCHEDULER,
        ProjectFileType::TEMPLATE,
        ProjectFileType::CONFIG,
        ProjectFileType::PHP,
    ];

    /** @var int<1, max> */
    private int $chunkSize;

    public function __construct(
        private ChunkingStrategy $chunkingStrategy = ChunkingStrategy::Feature,
        int $chunkSize = self::DEFAULT_CHUNK_SIZE,
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
            if (ProjectFileType::CONTROLLER !== $file->fileType()) {
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
        $featureName = u(basename($projectFile->relativePath(), '.php'))->beforeLast('Controller')->toString();

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
        $baseName = basename(basename($projectFile->relativePath(), '.php'), '.twig');
        $relativePath = $projectFile->relativePath();

        foreach ($featureNames as $featureName) {
            if ($this->fileBelongsToFeature($baseName, $relativePath, $featureName)) {
                return $featureName;
            }
        }

        return null;
    }

    private function fileBelongsToFeature(string $baseName, string $relativePath, string $featureName): bool
    {
        if (u($baseName)->startsWith($featureName)) {
            return true;
        }

        return u($relativePath)->ignoreCase()->containsAny(\sprintf('/%s/', $featureName));
    }

    private function priority(ProjectFile $projectFile): int
    {
        $index = array_search($projectFile->fileType(), self::TYPE_PRIORITY, true);

        return false !== $index ? $index : \count(self::TYPE_PRIORITY);
    }
}
