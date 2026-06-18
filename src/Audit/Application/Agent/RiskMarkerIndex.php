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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Indexes pre-scan risk markers by file path and answers the two questions the
 * attacker agent asks of them: which markers belong to a given chunk, and which
 * files carry at least one marker (used by lean mode to skip inert files).
 */
final readonly class RiskMarkerIndex
{
    /** @var array<string, list<RiskMarker>> */
    private array $byFile;

    /**
     * @param list<RiskMarker> $markers
     */
    public function __construct(array $markers)
    {
        $byFile = [];
        foreach ($markers as $marker) {
            $byFile[$marker->filePath()][] = $marker;
        }

        $this->byFile = $byFile;
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @return list<RiskMarker>
     */
    public function forChunk(array $chunk): array
    {
        $markers = [];
        foreach ($chunk as $file) {
            foreach ($this->byFile[$file->relativePath()] ?? [] as $marker) {
                $markers[] = $marker;
            }
        }

        return $markers;
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<ProjectFile>
     */
    public function filesWithMarkers(array $files): array
    {
        return array_values(array_filter(
            $files,
            fn (ProjectFile $projectFile): bool => array_key_exists($projectFile->relativePath(), $this->byFile),
        ));
    }
}
