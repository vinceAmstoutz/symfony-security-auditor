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
use InvalidArgumentException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

final class AuditContext implements CoverageRecorderInterface
{
    /** @var list<ProjectFile> */
    private array $projectFiles = [];

    private ?SymfonyMapping $symfonyMapping = null;

    /** @var array<string, Vulnerability> keyed by vulnerability id */
    private array $vulnerabilities = [];

    /** @var array<string, mixed> */
    private array $metadata = [];

    /** @var list<array{stage: string, file: string, status: string}> */
    private array $coverage = [];

    private DateTimeImmutable $startedAt;

    private function __construct(
        private readonly string $projectPath,
        private readonly string $auditId,
    ) {
        $this->startedAt = new DateTimeImmutable();
    }

    public static function forProject(string $projectPath): self
    {
        if (!is_dir($projectPath)) {
            throw new InvalidArgumentException(\sprintf('Project path "%s" is not a valid directory', $projectPath));
        }

        return new self(
            projectPath: rtrim($projectPath, '/'),
            auditId: \sprintf('AUDIT-%s', strtoupper(bin2hex(random_bytes(4)))),
        );
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

    /** @return list<ProjectFile> */
    public function projectFiles(): array
    {
        return $this->projectFiles;
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
}
