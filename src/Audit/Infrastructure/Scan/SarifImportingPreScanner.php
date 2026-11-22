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
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidRiskMarkerException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\BoundedFileReader;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\UnreadableInputFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\MalformedSarifFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\SarifFileNotReadableException;

use function Symfony\Component\String\u;

/**
 * Adds to the decorated pre-scanner's markers one `sarif:<tool>:<rule>` marker
 * per result of the `scan.import_sarif` SARIF 2.1.0 reports that points at a
 * scanned file. Drops a result pointing at any other file.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
        private SarifTaintPathFormatter $sarifTaintPathFormatter = new SarifTaintPathFormatter(),
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
            $decoded = json_decode(BoundedFileReader::read($path), true, flags: \JSON_THROW_ON_ERROR);
        } catch (UnreadableInputFileException $unreadableInputFileException) {
            throw SarifFileNotReadableException::fromUnreadableFile($path, $unreadableInputFileException);
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
            $this->describeWithTaintPath($message, $result, $scannedPaths),
        );
    }

    /**
     * @param array<array-key, mixed> $result
     * @param array<string, true>     $scannedPaths
     */
    private function describeWithTaintPath(string $message, array $result, array $scannedPaths): string
    {
        return $this->sarifTaintPathFormatter->describe($message, $this->taintPathSteps($result, $scannedPaths));
    }

    /**
     * The source-to-sink steps of `codeFlows[0].threadFlows[0].locations`, a
     * step in a file the scan does not hold as `null`.
     *
     * @param array<array-key, mixed> $result
     * @param array<string, true>     $scannedPaths
     *
     * @return list<string|null>
     */
    private function taintPathSteps(array $result, array $scannedPaths): array
    {
        $locations = $this->valueAt($result, ['codeFlows', 0, 'threadFlows', 0, 'locations']);
        if (!\is_array($locations)) {
            return [];
        }

        $rawSteps = [];
        foreach ($locations as $location) {
            $rawSteps[] = \is_array($location) ? $this->taintPathStep($location, $scannedPaths) : null;
        }

        return $rawSteps;
    }

    /**
     * @param array<array-key, mixed> $location
     * @param array<string, true>     $scannedPaths
     */
    private function taintPathStep(array $location, array $scannedPaths): ?string
    {
        $uri = $this->stringAt($location, ['location', 'physicalLocation', 'artifactLocation', 'uri']);
        if (null === $uri) {
            return null;
        }

        $relativePath = $this->normalizeUri($uri);
        if (!\array_key_exists($relativePath, $scannedPaths)) {
            return null;
        }

        $startLine = $this->valueAt($location, ['location', 'physicalLocation', 'region', 'startLine']);

        return \sprintf('%s:%d', $relativePath, \is_int($startLine) ? max(1, $startLine) : 1);
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
     * The project-relative path of an artifact URI, whichever spelling the
     * producer used (`src/A.php`, `./src/A.php`, `file:///<root>/src/A.php`,
     * `src/my%20page.twig`).
     */
    private function normalizeUri(string $uri): string
    {
        $normalized = u(WindowsDrivePath::normalize($this->decodePercentEncoding($uri)))->trimPrefix('./');
        $projectRootPrefix = u(WindowsDrivePath::normalize($this->auditedProjectPathHolder->path()))->ensureEnd('/');

        return $normalized->trimPrefix($projectRootPrefix->toString())->trimStart('/')->toString();
    }

    /**
     * Leaves an invalid escape sequence untouched, so a raw path still
     * matches.
     */
    private function decodePercentEncoding(string $uri): string
    {
        return rawurldecode(u($uri)->trimPrefix('file://')->toString());
    }
}
