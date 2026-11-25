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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ScrubbedSecretFindings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\StaticMarkerFindings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CandidateFindingSourceInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class CandidateFindingSource implements CandidateFindingSourceInterface
{
    public const int MAX_CANDIDATES_PER_PATTERN = 20;

    public function __construct(
        private StaticPreScannerInterface $staticPreScanner,
        private bool $enabled = true,
    ) {}

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<Vulnerability>
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[Override]
    public function candidatesIn(array $files): array
    {
        if (!$this->enabled) {
            return [];
        }

        return [...$this->scrubbedSecrets($files), ...$this->staticMatches($files)];
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<Vulnerability>
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function scrubbedSecrets(array $files): array
    {
        $findings = [];
        foreach ($files as $file) {
            array_push($findings, ...ScrubbedSecretFindings::in($file));
        }

        return $findings;
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<Vulnerability>
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function staticMatches(array $files): array
    {
        $markersByPath = [];
        foreach ($this->staticPreScanner->scan($files) as $riskMarker) {
            $markersByPath[$riskMarker->filePath()][] = $riskMarker;
        }

        $filesByPath = [];
        foreach ($files as $file) {
            $filesByPath[$file->relativePath()] = $file;
        }

        $findings = [];
        foreach ($markersByPath as $path => $riskMarkers) {
            array_push($findings, ...$this->findingsOnLines(explode("\n", ($filesByPath[$path] ?? null)?->content() ?? ''), $riskMarkers));
        }

        return $findings;
    }

    /**
     * Lists at most {@see self::MAX_CANDIDATES_PER_PATTERN} findings per
     * pattern of one file.
     *
     * @param list<string>     $lines       the lines of the file the markers are in
     * @param list<RiskMarker> $riskMarkers
     *
     * @return list<Vulnerability>
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function findingsOnLines(array $lines, array $riskMarkers): array
    {
        $findings = [];
        $listedPerPattern = [];
        foreach ($riskMarkers as $riskMarker) {
            $listed = $listedPerPattern[$riskMarker->pattern()] ?? 0;
            if ($listed >= self::MAX_CANDIDATES_PER_PATTERN) {
                continue;
            }

            $finding = StaticMarkerFindings::from($riskMarker, $lines[$riskMarker->line() - 1] ?? '');
            if ($finding instanceof Vulnerability) {
                $findings[] = $finding;
                $listedPerPattern[$riskMarker->pattern()] = $listed + 1;
            }
        }

        return $findings;
    }
}
