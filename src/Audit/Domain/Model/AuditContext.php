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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

use DateTimeImmutable;
use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

final class AuditContext implements CoverageRecorderInterface
{
    /** @var list<ProjectFile> */
    private array $projectFiles = [];

    /** @var ?list<ProjectFile> */
    private ?array $mappingFiles = null;

    private ?SymfonyMapping $symfonyMapping = null;

    /** @var array<string, Vulnerability> keyed by vulnerability id */
    private array $vulnerabilities = [];

    /** @var array<string, mixed> */
    private array $metadata = [];

    /** @var list<array{stage: string, file: string, status: string}> */
    private array $coverage = [];

    /** @var list<Vulnerability> */
    private array $pendingReviewedFindings = [];

    /** @var list<Vulnerability> */
    private array $pendingFoundVulnerabilities = [];

    /** @var ?array<string, int> */
    private ?array $remainingBaselineBudget = null;

    /** @var list<string> */
    private array $consumedBaselineFingerprints = [];

    private DateTimeImmutable $startedAt;

    /**
     * @param list<string> $scanPaths
     * @param list<string> $acceptedFingerprints
     */
    private function __construct(
        private readonly string $projectPath,
        private readonly string $auditId,
        private readonly array $scanPaths,
        private readonly bool $cacheBypassed,
        private readonly ?string $diffSinceRef = null,
        private readonly array $acceptedFingerprints = [],
    ) {
        $this->startedAt = new DateTimeImmutable();
    }

    /**
     * @param list<string> $scanPaths            optional project-relative subdirectories
     *                                           that the scan should be restricted to;
     *                                           empty list scans the whole project
     * @param bool         $cacheBypassed        when true, agents should skip the
     *                                           attacker cache entirely for this run
     *                                           (no reads, no writes)
     * @param ?string      $diffSinceRef         when set, the IngestionStage filters
     *                                           discovered files down to those changed
     *                                           against this git ref (diff mode); null
     *                                           (default) audits every file in scope
     * @param list<string> $acceptedFingerprints
     *                                           baseline fingerprints of accepted
     *                                           findings; matching attacker findings
     *                                           are dropped before the reviewer runs
     *
     * @throws InvalidAuditContextException
     */
    public static function forProject(string $projectPath, array $scanPaths = [], bool $cacheBypassed = false, ?string $diffSinceRef = null, array $acceptedFingerprints = []): self
    {
        if (!is_dir($projectPath)) {
            throw InvalidAuditContextException::forInvalidProjectPath($projectPath);
        }

        $trimmedProjectPath = rtrim($projectPath, '/');

        return new self(
            projectPath: '' === $trimmedProjectPath ? '/' : $trimmedProjectPath,
            auditId: \sprintf('AUDIT-%s', strtoupper(bin2hex(random_bytes(4)))),
            scanPaths: $scanPaths,
            cacheBypassed: $cacheBypassed,
            diffSinceRef: $diffSinceRef,
            acceptedFingerprints: $acceptedFingerprints,
        );
    }

    /** @return list<string> */
    public function acceptedFingerprints(): array
    {
        return $this->acceptedFingerprints;
    }

    /**
     * Spends one baseline credit for `$fingerprint`, shared across every
     * caller and every attacker/reviewer iteration of this run — the budget
     * is seeded once from `$acceptedFingerprints` (`array_count_values()`
     * semantics: an accepted fingerprint repeated N times grants N credits)
     * and decrements monotonically, so the same accepted occurrence can never
     * be spent twice regardless of how many times or where it is offered.
     */
    public function consumeBaselineCredit(string $fingerprint): bool
    {
        $this->remainingBaselineBudget ??= array_count_values($this->acceptedFingerprints);

        if (($this->remainingBaselineBudget[$fingerprint] ?? 0) <= 0) {
            return false;
        }

        --$this->remainingBaselineBudget[$fingerprint];
        $this->consumedBaselineFingerprints[] = $fingerprint;

        return true;
    }

    /** @return list<string> */
    public function consumedBaselineFingerprints(): array
    {
        return $this->consumedBaselineFingerprints;
    }

    public function diffSinceRef(): ?string
    {
        return $this->diffSinceRef;
    }

    public function projectPath(): string
    {
        return $this->projectPath;
    }

    public function auditId(): string
    {
        return $this->auditId;
    }

    public function startedAt(): DateTimeImmutable
    {
        return $this->startedAt;
    }

    /** @return list<string> */
    public function scanPaths(): array
    {
        return $this->scanPaths;
    }

    public function isCacheBypassed(): bool
    {
        return $this->cacheBypassed;
    }

    /** @return list<ProjectFile> */
    public function projectFiles(): array
    {
        return $this->projectFiles;
    }

    /**
     * The files `MappingStage` builds `SymfonyMapping`/`AccessControlMap`
     * from — the full scan scope, unlike {@see self::projectFiles()}, which
     * a `--since` diff-mode run narrows to only the changed files. Falls
     * back to {@see self::projectFiles()} when `IngestionStage` never calls
     * {@see self::setMappingFiles()} (a full, non-diff run, or a test that
     * only sets `projectFiles`), since the two are identical in that case.
     *
     * @return list<ProjectFile>
     */
    public function mappingFiles(): array
    {
        return $this->mappingFiles ?? $this->projectFiles;
    }

    public function mapping(): ?SymfonyMapping
    {
        return $this->symfonyMapping;
    }

    /** @return array<string, Vulnerability> */
    public function vulnerabilities(): array
    {
        return $this->vulnerabilities;
    }

    /** @param list<ProjectFile> $files */
    public function setProjectFiles(array $files): void
    {
        $this->projectFiles = $files;
    }

    /** @param list<ProjectFile> $files */
    public function setMappingFiles(array $files): void
    {
        $this->mappingFiles = $files;
    }

    public function setMapping(SymfonyMapping $symfonyMapping): void
    {
        $this->symfonyMapping = $symfonyMapping;
    }

    public function addVulnerability(Vulnerability $vulnerability): void
    {
        $this->vulnerabilities[$vulnerability->id()] = $vulnerability;
    }

    public function replaceVulnerability(Vulnerability $vulnerability): void
    {
        $this->vulnerabilities[$vulnerability->id()] = $vulnerability;
    }

    public function setMeta(string $key, mixed $value): void
    {
        $this->metadata[$key] = $value;
    }

    public function getMeta(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }

    /** @return array<string, Vulnerability> */
    public function validatedVulnerabilities(): array
    {
        return array_filter(
            $this->vulnerabilities,
            static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(),
        );
    }

    /** @return array<string, Vulnerability> */
    public function criticalVulnerabilities(): array
    {
        return array_filter(
            $this->vulnerabilities,
            static fn (Vulnerability $vulnerability): bool => VulnerabilitySeverity::CRITICAL === $vulnerability->severity()
                && $vulnerability->isReviewerValidated(),
        );
    }

    public function riskScore(): int
    {
        return array_sum(
            array_map(
                static fn (Vulnerability $vulnerability): int => $vulnerability->severity()->score(),
                $this->validatedVulnerabilities(),
            ),
        );
    }

    #[Override]
    public function recordCoverage(string $stage, string $filePath, string $status): void
    {
        $this->coverage[] = ['stage' => $stage, 'file' => $filePath, 'status' => $status];
    }

    /**
     * @return list<array{stage: string, file: string, status: string}>
     */
    public function coverage(): array
    {
        return $this->coverage;
    }

    #[Override]
    public function recordReviewedFinding(Vulnerability $vulnerability): void
    {
        $this->pendingReviewedFindings[] = $vulnerability;
    }

    #[Override]
    public function drainReviewedFindings(): array
    {
        $drained = $this->pendingReviewedFindings;
        $this->pendingReviewedFindings = [];

        return $drained;
    }

    #[Override]
    public function recordFoundVulnerability(Vulnerability $vulnerability): void
    {
        $this->pendingFoundVulnerabilities[] = $vulnerability;
    }

    #[Override]
    public function drainFoundVulnerabilities(): array
    {
        $drained = $this->pendingFoundVulnerabilities;
        $this->pendingFoundVulnerabilities = [];

        return $drained;
    }
}
