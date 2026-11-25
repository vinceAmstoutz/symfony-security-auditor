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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\FindingReviewRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\RejectedFindingRecorderInterface;

final class AuditContext implements CoverageRecorderInterface, RejectedFindingRecorderInterface, FindingReviewRecorderInterface
{
    /** @var list<ProjectFile> */
    private array $projectFiles = [];

    /** @var ?list<ProjectFile> */
    private ?array $mappingFiles = null;

    private ?int $filesDiscovered = null;

    private ?SymfonyMapping $symfonyMapping = null;

    /** @var array<string, Vulnerability> keyed by vulnerability id */
    private array $vulnerabilities = [];

    /** @var array<string, array<string, true>> the ids of the vulnerabilities of each file */
    private array $vulnerabilityIdsByFile = [];

    /** @var array<string, mixed> */
    private array $metadata = [];

    /** @var array<int, array{stage: string, file: string, status: string}> */
    private array $coverage = [];

    /** @var array<string, list<int>> the ledger positions of the review failures recorded for a finding, by vulnerability id */
    private array $reviewFailurePositions = [];

    /** @var list<Vulnerability> */
    private array $pendingReviewedFindings = [];

    /** @var list<Vulnerability> */
    private array $pendingFoundVulnerabilities = [];

    /** @var list<Vulnerability> */
    private array $staticCandidates = [];

    /** @var array<string, true> keyed by vulnerability id */
    private array $rejectedFindingIds = [];

    /** @var ?array<string, int> */
    private ?array $remainingBaselineBudget = null;

    /** @var list<SuppressedFinding> */
    private array $baselineAcceptedFindings = [];

    /** @var list<Vulnerability> */
    private array $baselineSkippedFindings = [];

    /** @var array<string, list<Vulnerability>> */
    private array $baselineSkippedFindingsByFingerprint = [];

    private bool $costEstimate = false;

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
     * @param list<string> $scanPaths            project-relative subdirectories the
     *                                           scan is restricted to; empty scans
     *                                           the whole project
     * @param bool         $cacheBypassed        skips the attacker cache, reads and
     *                                           writes alike
     * @param ?string      $diffSinceRef         narrows the run to the files changed
     *                                           against this git ref; null audits
     *                                           every file in scope
     * @param list<string> $acceptedFingerprints
     *                                           baseline fingerprints of accepted
     *                                           findings, dropped before review
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
     * Spends one baseline credit for `$fingerprint`; false when none is left.
     * A fingerprint accepted N times grants N credits for the whole run, so no
     * accepted occurrence is ever spent twice.
     */
    public function consumeBaselineCredit(string $fingerprint): bool
    {
        return $this->spendBaselineCredit(new SuppressedFinding($fingerprint, $fingerprint));
    }

    /**
     * Spends one baseline credit on `$vulnerability`, trying each of its
     * `Vulnerability::fingerprintCandidates()` in order.
     */
    public function consumeBaselineCreditFor(Vulnerability $vulnerability): bool
    {
        foreach ($vulnerability->fingerprintCandidates() as $fingerprintCandidate) {
            if ($this->spendBaselineCredit(new SuppressedFinding($vulnerability->fingerprint(), $fingerprintCandidate))) {
                return true;
            }
        }

        return false;
    }

    private function spendBaselineCredit(SuppressedFinding $suppressedFinding): bool
    {
        $this->remainingBaselineBudget ??= array_count_values($this->acceptedFingerprints);
        $fingerprint = $suppressedFinding->baselineFingerprint;

        if (!\array_key_exists($fingerprint, $this->remainingBaselineBudget) || $this->remainingBaselineBudget[$fingerprint] <= 0) {
            return false;
        }

        --$this->remainingBaselineBudget[$fingerprint];
        $this->baselineAcceptedFindings[] = $suppressedFinding;

        return true;
    }

    /** @return list<string> */
    public function consumedBaselineFingerprints(): array
    {
        return array_map(
            static fn (SuppressedFinding $suppressedFinding): string => $suppressedFinding->baselineFingerprint,
            $this->baselineAcceptedFindings,
        );
    }

    /**
     * The findings whose baseline credit was spent, each under its own
     * fingerprint beside the baseline fingerprint it spent.
     *
     * @internal not part of the BC promise, see docs/versioning.md
     *
     * @return list<SuppressedFinding>
     */
    public function baselineAcceptedFindings(): array
    {
        return $this->baselineAcceptedFindings;
    }

    /**
     * Remembers a finding whose baseline credit was spent before review, so a
     * later iteration that re-reports it is skipped again.
     */
    public function recordBaselineSkippedFinding(Vulnerability $vulnerability): void
    {
        $this->baselineSkippedFindings[] = $vulnerability;
        $this->baselineSkippedFindingsByFingerprint[$vulnerability->fingerprint()][] = $vulnerability;
    }

    /**
     * The baseline-skipped findings under `$fingerprint`, in the order they
     * were skipped.
     *
     * @internal not part of the BC promise, see docs/versioning.md
     *
     * @return list<Vulnerability>
     */
    public function baselineSkippedFindingsWith(string $fingerprint): array
    {
        return $this->baselineSkippedFindingsByFingerprint[$fingerprint] ?? [];
    }

    /** @return list<Vulnerability> */
    public function baselineSkippedFindings(): array
    {
        return $this->baselineSkippedFindings;
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

    /**
     * Marks the run as a `--dry-run` cost estimate, which analyzes no file, so
     * its report never reads as complete.
     */
    public function markAsCostEstimate(): void
    {
        $this->costEstimate = true;
    }

    public function isCostEstimate(): bool
    {
        return $this->costEstimate;
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
     * The files the mapping is built from: the full scan scope, which a
     * `--since` run does not narrow. Equals {@see self::projectFiles()} until
     * {@see self::setMappingFiles()} is called.
     *
     * @return list<ProjectFile>
     */
    public function mappingFiles(): array
    {
        return $this->mappingFiles ?? $this->projectFiles;
    }

    /**
     * How many files the scan found in scope before a `--since` diff narrowed
     * them. The count of {@see self::mappingFiles()} until
     * {@see self::setFilesDiscovered()} is called.
     */
    public function filesDiscovered(): int
    {
        return $this->filesDiscovered ?? \count($this->mappingFiles());
    }

    public function mapping(): ?SymfonyMapping
    {
        return $this->symfonyMapping;
    }

    /**
     * The mapping under the framework-neutral names pipeline stages read.
     */
    public function securityMap(): ?ApplicationSecurityMap
    {
        return $this->symfonyMapping?->toApplicationSecurityMap();
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

    public function setFilesDiscovered(int $filesDiscovered): void
    {
        $this->filesDiscovered = $filesDiscovered;
    }

    public function setMapping(SymfonyMapping $symfonyMapping): void
    {
        $this->symfonyMapping = $symfonyMapping;
    }

    public function addVulnerability(Vulnerability $vulnerability): void
    {
        $this->vulnerabilities[$vulnerability->id()] = $vulnerability;
        $this->vulnerabilityIdsByFile[$vulnerability->filePath()][$vulnerability->id()] = true;
    }

    public function replaceVulnerability(Vulnerability $vulnerability): void
    {
        $this->addVulnerability($vulnerability);
    }

    public function removeVulnerability(string $id): void
    {
        $vulnerability = $this->vulnerabilities[$id] ?? null;
        if ($vulnerability instanceof Vulnerability) {
            unset($this->vulnerabilityIdsByFile[$vulnerability->filePath()][$id]);
        }

        unset($this->vulnerabilities[$id]);
    }

    /**
     * The vulnerabilities of one file, by id.
     *
     * @internal not part of the BC promise, see docs/versioning.md
     *
     * @return array<string, Vulnerability>
     */
    public function vulnerabilitiesIn(string $filePath): array
    {
        $vulnerabilities = [];
        foreach (array_keys($this->vulnerabilityIdsByFile[$filePath] ?? []) as $id) {
            $vulnerabilities[$id] = $this->vulnerabilities[$id];
        }

        return $vulnerabilities;
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
        $this->appendCoverage($stage, $filePath, $status);
    }

    #[Override]
    public function recordFindingReview(Vulnerability $vulnerability, string $status): void
    {
        $position = $this->appendCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), $status);

        if ('validated' === $status || 'rejected' === $status) {
            $this->supersedeReviewFailures($vulnerability);

            return;
        }

        $this->reviewFailurePositions[$vulnerability->id()][] = $position;
    }

    /**
     * @return list<array{stage: string, file: string, status: string}>
     */
    public function coverage(): array
    {
        return array_values($this->coverage);
    }

    private function appendCoverage(string $stage, string $filePath, string $status): int
    {
        $this->coverage[] = ['stage' => $stage, 'file' => $filePath, 'status' => $status];

        return array_key_last($this->coverage);
    }

    private function supersedeReviewFailures(Vulnerability $vulnerability): void
    {
        foreach ($this->reviewFailurePositions[$vulnerability->id()] ?? [] as $position) {
            unset($this->coverage[$position]);
        }
    }

    #[Override]
    public function recordReviewedFinding(Vulnerability $vulnerability): void
    {
        $this->pendingReviewedFindings[] = $vulnerability;
    }

    #[Override]
    public function recordRejectedFinding(Vulnerability $vulnerability): void
    {
        $this->rejectedFindingIds[$vulnerability->id()] = true;
    }

    /**
     * Whether the reviewer reached a rejecting verdict on this finding, as
     * opposed to a review that failed.
     */
    public function wasRejectedByReviewer(Vulnerability $vulnerability): bool
    {
        return \array_key_exists($vulnerability->id(), $this->rejectedFindingIds);
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

    public function addStaticCandidate(Vulnerability $vulnerability): void
    {
        $this->staticCandidates[] = $vulnerability;
    }

    /**
     * @return list<Vulnerability>
     */
    public function drainStaticCandidates(): array
    {
        $drained = $this->staticCandidates;
        $this->staticCandidates = [];

        return $drained;
    }
}
