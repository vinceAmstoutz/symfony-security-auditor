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

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class FileChunker
{
    private const int DEFAULT_CHUNK_SIZE = 10;

    private const array TYPE_PRIORITY = [
        'controller',
        'authenticator',
        'voter',
        'webhook_consumer',
        'messenger_handler',
        'event_subscriber',
        'normalizer',
        'entity',
        'repository',
        'form',
        'scheduler',
        'template',
        'config',
        'php',
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
        usort($files, fn (ProjectFile $a, ProjectFile $b): int => $this->priority($a) <=> $this->priority($b));

        return array_chunk($files, $this->chunkSize);
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

            usort($featureFiles, fn (ProjectFile $a, ProjectFile $b): int => $this->priority($a) <=> $this->priority($b));

            foreach (array_chunk($featureFiles, $this->chunkSize) as $sliceOfFeature) {
                $chunks[] = $sliceOfFeature;
            }

            foreach ($featureFiles as $featureFile) {
                $assignedPaths[$featureFile->relativePath()] = true;
            }
        }

        $leftovers = array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => !isset($assignedPaths[$projectFile->relativePath()]),
        ));

        if ([] !== $leftovers) {
            usort($leftovers, fn (ProjectFile $a, ProjectFile $b): int => $this->priority($a) <=> $this->priority($b));

            foreach (array_chunk($leftovers, $this->chunkSize) as $leftoverChunk) {
                $chunks[] = $leftoverChunk;
            }
        }

        return $chunks;
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
            if ('controller' !== $file->type()) {
                continue;
            }

            $baseName = basename($file->relativePath(), '.php');

            if (!str_ends_with($baseName, 'Controller')) {
                continue;
            }

            $featureName = substr($baseName, 0, -\strlen('Controller'));

            if ('' === $featureName) {
                continue;
            }

            $names[$featureName] = true;
        }

        return array_keys($names);
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
        $baseName = basename($projectFile->relativePath(), '.php');
        $baseName = basename($baseName, '.twig');

        $relativePath = $projectFile->relativePath();

        foreach ($featureNames as $featureName) {
            if ($baseName === $featureName) {
                return $featureName;
            }

            if (str_starts_with($baseName, $featureName)) {
                return $featureName;
            }

            $lowerFeature = strtolower($featureName);
            if (str_contains(strtolower($relativePath), '/'.$lowerFeature.'/')) {
                return $featureName;
            }
        }

        return null;
    }

    private function priority(ProjectFile $projectFile): int
    {
        $index = array_search($projectFile->type(), self::TYPE_PRIORITY, true);

        return false !== $index ? $index : \count(self::TYPE_PRIORITY);
    }
}
