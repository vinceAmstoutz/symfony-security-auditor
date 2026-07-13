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

use JsonException;
use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\MalformedSarifFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\SarifFileNotReadableException;

use function Symfony\Component\String\u;

/**
 * Decorates another pre-scanner and merges in risk markers imported from
 * configured SARIF 2.1.0 report files (`scan.import_sarif`) — the output of
 * taint-tracking SAST tools like Psalm, Progpilot, PHPStan, or Semgrep. Each
 * SARIF result whose artifact URI matches a scanned file becomes a marker at
 * that file and line, labelled `sarif:<tool>:<rule>`, so the attacker starts
 * from the external tool's concrete leads. Results pointing at files outside
 * the scan surface are dropped — the attacker never sees those files, so a
 * marker there could only hallucinate context.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SarifImportingPreScanner implements StaticPreScannerInterface
{
    /**
     * @param list<string> $sarifPaths relative paths resolve against the audited project root
     */
    public function __construct(
        private StaticPreScannerInterface $staticPreScanner,
        private array $sarifPaths,
        private Filesystem $filesystem,
        private AuditedProjectPathHolder $auditedProjectPathHolder,
    ) {}

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<RiskMarker>
     *
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    #[Override]
    public function scan(array $files): array
    {
        $scannedPaths = [];
        foreach ($files as $file) {
            $scannedPaths[$file->relativePath()] = true;
        }

        $markers = $this->staticPreScanner->scan($files);
        foreach ($this->sarifPaths as $sarifPath) {
            foreach ($this->importMarkers($this->resolvePath($sarifPath), $scannedPaths) as $riskMarker) {
                $markers[] = $riskMarker;
            }
        }

        return $markers;
    }

    private function resolvePath(string $sarifPath): string
    {
        return Path::isAbsolute($sarifPath) ? $sarifPath : Path::join($this->auditedProjectPathHolder->path(), $sarifPath);
    }

    /**
     * @param array<string, true> $scannedPaths
     *
     * @return list<RiskMarker>
     *
     * @throws InvalidRiskMarkerException
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    private function importMarkers(string $path, array $scannedPaths): array
    {
        $markers = [];
        foreach ($this->decodeRuns($path) as $run) {
            if (!\is_array($run)) {
                continue;
            }

            foreach ($this->markersFromRun($run, $scannedPaths) as $riskMarker) {
                $markers[] = $riskMarker;
            }
        }

        return $markers;
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws SarifFileNotReadableException
     * @throws MalformedSarifFileException
     */
    private function decodeRuns(string $path): array
    {
        if (!$this->filesystem->exists($path)) {
            throw SarifFileNotReadableException::forPath($path);
        }

        try {
            $decoded = json_decode($this->filesystem->readFile($path), true, flags: \JSON_THROW_ON_ERROR);
        } catch (IOException $ioException) {
            throw SarifFileNotReadableException::forPath($path, $ioException);
        } catch (JsonException $jsonException) {
            throw MalformedSarifFileException::fromJsonException($path, $jsonException);
        }

        $runs = \is_array($decoded) ? ($decoded['runs'] ?? null) : null;
        if (!\is_array($runs)) {
            throw MalformedSarifFileException::missingRunsArray($path);
        }

        return $runs;
    }

    /**
     * @param array<array-key, mixed> $run
     * @param array<string, true>     $scannedPaths
     *
     * @return list<RiskMarker>
     *
     * @throws InvalidRiskMarkerException
     */
    private function markersFromRun(array $run, array $scannedPaths): array
    {
        $toolName = $this->stringAt($run, ['tool', 'driver', 'name']) ?? 'sarif';
        $results = $run['results'] ?? [];
        if (!\is_array($results)) {
            return [];
        }

        $markers = [];
        foreach ($results as $result) {
            $riskMarker = \is_array($result) ? $this->markerFromResult($result, $toolName, $scannedPaths) : null;
            if ($riskMarker instanceof RiskMarker) {
                $markers[] = $riskMarker;
            }
        }

        return $markers;
    }

    /**
     * @param array<array-key, mixed> $result
     * @param array<string, true>     $scannedPaths
     *
     * @throws InvalidRiskMarkerException
     */
    private function markerFromResult(array $result, string $toolName, array $scannedPaths): ?RiskMarker
    {
        $uri = $this->stringAt($result, ['locations', 0, 'physicalLocation', 'artifactLocation', 'uri']);
        if (null === $uri) {
            return null;
        }

        $relativePath = $this->normalizeUri($uri);
        if (!\array_key_exists($relativePath, $scannedPaths)) {
            return null;
        }

        $ruleId = $this->stringAt($result, ['ruleId']) ?? 'result';
        $message = $this->stringAt($result, ['message', 'text']) ?? $ruleId;

        return RiskMarker::create(
            $relativePath,
            $this->startLineOf($result),
            \sprintf('sarif:%s:%s', $toolName, $ruleId),
            $message,
        );
    }

    /**
     * @param array<array-key, mixed> $result
     */
    private function startLineOf(array $result): int
    {
        $startLine = $this->valueAt($result, ['locations', 0, 'physicalLocation', 'region', 'startLine']);

        return \is_int($startLine) ? max(1, $startLine) : 1;
    }

    /**
     * @param array<array-key, mixed> $data
     * @param list<array-key>         $keys
     */
    private function stringAt(array $data, array $keys): ?string
    {
        $value = $this->valueAt($data, $keys);
        if (!\is_string($value) || u($value)->trim()->isEmpty()) {
            return null;
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $data
     * @param list<array-key>         $keys
     */
    private function valueAt(array $data, array $keys): mixed
    {
        $value = $data;
        foreach ($keys as $key) {
            if (!\is_array($value) || !\array_key_exists($key, $value)) {
                return null;
            }

            $value = $value[$key];
        }

        return $value;
    }

    /**
     * SARIF producers emit artifact URIs in several equivalent spellings for
     * the same repository-relative file (`src/A.php`, `./src/A.php`,
     * `file:///<project root>/src/A.php` when no uriBaseId applies) —
     * normalize to the project-relative form the scanner uses.
     */
    private function normalizeUri(string $uri): string
    {
        $normalized = u($uri)->trimPrefix('file://')->trimPrefix('./');
        $projectRootPrefix = u($this->auditedProjectPathHolder->path())->ensureEnd('/');

        return $normalized->trimPrefix($projectRootPrefix->toString())->trimStart('/')->toString();
    }
}
