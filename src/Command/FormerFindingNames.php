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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EchoedFilePath;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;

/**
 * The names a baseline written before 1.22 may hold a finding under while the
 * report names it otherwise: the path the model echoed for it (`./src/A.php`,
 * `src\A.php`, `/src/A.php`, an absolute path inside the report's project),
 * which the finding now trades for its project file, and the types it was
 * reported as before its own type existed — the fingerprints
 * `Vulnerability::fingerprintCandidates()` lists after the finding's own.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FormerFindingNames
{
    /**
     * Whether `$baselineEntry` holds `$diffFinding` under one of its names. A
     * report written before 1.22 names each finding as the model did, so only
     * its own fingerprint matches it, as it always did.
     */
    public static function holds(BaselineEntry $baselineEntry, DiffFinding $diffFinding, LoadedReport $loadedReport): bool
    {
        return null !== $loadedReport->projectPath
            && \in_array($baselineEntry->fingerprint, self::formerFingerprintsOf($diffFinding, $baselineEntry->file(), $loadedReport->projectPath), true);
    }

    /**
     * @return list<string>
     */
    private static function formerFingerprintsOf(DiffFinding $diffFinding, ?string $entryFile, string $projectPath): array
    {
        $fingerprints = [];
        foreach (self::spellingsOf($diffFinding, $entryFile, $projectPath) as $filePath) {
            foreach (self::typesOf($diffFinding) as $type) {
                $fingerprints[] = Vulnerability::fingerprintOf($type, $filePath, $diffFinding->title);
            }
        }

        return $fingerprints;
    }

    /**
     * The finding's own path, then the entry's when it names the same file.
     *
     * @return list<string>
     */
    private static function spellingsOf(DiffFinding $diffFinding, ?string $entryFile, string $projectPath): array
    {
        return [
            $diffFinding->file,
            ...(null !== $entryFile && EchoedFilePath::denotes($entryFile, $diffFinding->file, \sprintf('%s/%s', $projectPath, $diffFinding->file)) ? [$entryFile] : []),
        ];
    }

    /**
     * @return list<string>
     */
    private static function typesOf(DiffFinding $diffFinding): array
    {
        return [
            $diffFinding->type,
            ...array_map(
                static fn (VulnerabilityType $vulnerabilityType): string => $vulnerabilityType->value,
                VulnerabilityType::tryFrom($diffFinding->type)?->formerTypes() ?? [],
            ),
        ];
    }
}
