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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use WeakMap;

/**
 * Hands the decorated pre-scanner each file once: a file it already scanned
 * gets the markers found then, in the order they were found.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class MemoizedStaticPreScanner implements StaticPreScannerInterface
{
    /**
     * @var WeakMap<ProjectFile, list<RiskMarker>>
     */
    private WeakMap $markersByFile;

    public function __construct(
        private StaticPreScannerInterface $staticPreScanner,
    ) {
        $this->markersByFile = new WeakMap();
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<RiskMarker>
     */
    #[Override]
    public function scan(array $files): array
    {
        $this->scanUnscanned($files);

        $markers = [];
        foreach ($files as $file) {
            array_push($markers, ...$this->markersByFile[$file]);
        }

        return $markers;
    }

    /**
     * @param list<ProjectFile> $files
     */
    private function scanUnscanned(array $files): void
    {
        $unscanned = [];
        foreach ($files as $file) {
            if (!$this->markersByFile->offsetExists($file)) {
                $unscanned[spl_object_id($file)] = $file;
            }
        }

        if ([] === $unscanned) {
            return;
        }

        $markersByPath = [];
        foreach ($this->staticPreScanner->scan(array_values($unscanned)) as $riskMarker) {
            $markersByPath[$riskMarker->filePath()][] = $riskMarker;
        }

        foreach ($unscanned as $file) {
            $this->markersByFile[$file] = $markersByPath[$file->relativePath()] ?? [];
        }
    }
}
