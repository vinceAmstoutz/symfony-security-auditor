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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ScrubbedSecretFindings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\StaticMarkerFindings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CandidateFindingSourceInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class CandidateFindingSource implements CandidateFindingSourceInterface
{
    public function __construct(private StaticPreScannerInterface $staticPreScanner) {}

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
        $linesByPath = [];
        foreach ($files as $file) {
            $linesByPath[$file->relativePath()] = explode("\n", $file->content());
        }

        $findings = [];
        foreach ($this->staticPreScanner->scan($files) as $riskMarker) {
            $finding = StaticMarkerFindings::from($riskMarker, $linesByPath[$riskMarker->filePath()][$riskMarker->line() - 1] ?? '');
            if ($finding instanceof Vulnerability) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }
}
