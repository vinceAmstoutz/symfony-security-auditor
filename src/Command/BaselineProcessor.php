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

use Override;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\Clock;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\BaselineWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;

/**
 * Generates and applies the accepted-finding baseline. The `--baseline` path
 * wins over the configured one.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class BaselineProcessor implements BaselineProcessorInterface
{
    public function __construct(
        private BaselineInterface $baseline,
        private ?string $configuredBaseline = null,
        private ClockInterface $clock = new Clock(),
    ) {}

    /**
     * @throws UnsafeBaselineWriteException
     * @throws BaselineWriteFailedException
     */
    #[Override]
    public function assertWritable(string $path, string $projectPath): void
    {
        $this->baseline->assertWritable($path, $projectPath);
    }

    #[Override]
    public function generate(AuditReport $auditReport, string $path): int
    {
        $entries = $this->entriesFor($auditReport);
        $this->baseline->save($path, $entries, $auditReport->projectPath());

        return \count($entries);
    }

    #[Override]
    public function apply(AuditReport $auditReport, ?string $cliBaseline): BaselineResult
    {
        $baselinePath = $cliBaseline ?? $this->configuredBaseline;
        if (null === $baselinePath) {
            return new BaselineResult($auditReport, 0, []);
        }

        $fingerprints = $this->baseline->load($baselinePath);
        if ([] === $fingerprints) {
            return new BaselineResult($auditReport, 0, $fingerprints);
        }

        $before = $auditReport->totalVulnerabilities();
        $remainingFingerprints = $this->withoutAlreadyConsumed($fingerprints, $auditReport->consumedBaselineFingerprints());
        $filtered = $auditReport
            ->withoutFingerprints($remainingFingerprints)
            ->withFindingsAcceptedBeforeReviewNamedBy($this->entryFingerprintsByBaselineFingerprint($this->baseline->entries($baselinePath)));

        return new BaselineResult($filtered, $before - $filtered->totalVulnerabilities(), $fingerprints);
    }

    #[Override]
    public function acceptedFingerprints(?string $cliBaseline): array
    {
        $baselinePath = $cliBaseline ?? $this->configuredBaseline;
        if (null === $baselinePath) {
            return [];
        }

        return $this->baseline->load($baselinePath);
    }

    #[Override]
    public function filePaths(?string $cliBaseline): array
    {
        $baselinePath = $cliBaseline ?? $this->configuredBaseline;
        if (null === $baselinePath) {
            return [];
        }

        $filePaths = [];
        foreach ($this->baseline->entries($baselinePath) as $baselineEntry) {
            $file = $baselineEntry->file();
            if (null !== $file) {
                $filePaths[] = $file;
            }
        }

        return $filePaths;
    }

    #[Override]
    public function feedback(?string $cliBaseline): ReviewerFeedback
    {
        $baselinePath = $cliBaseline ?? $this->configuredBaseline;
        if (null === $baselinePath) {
            return ReviewerFeedback::none();
        }

        return $this->baseline->feedback($baselinePath);
    }

    /**
     * Removes one credit per occurrence the run already spent before review,
     * so no finding gets a second credit.
     *
     * @param list<string> $fingerprints
     * @param list<string> $alreadyConsumed
     *
     * @return list<string>
     */
    private function withoutAlreadyConsumed(array $fingerprints, array $alreadyConsumed): array
    {
        foreach ($alreadyConsumed as $consumedFingerprint) {
            $index = array_search($consumedFingerprint, $fingerprints, true);
            if (false !== $index) {
                unset($fingerprints[$index]);
            }
        }

        return array_values($fingerprints);
    }

    /**
     * The `fingerprint` of every entry under each fingerprint it carries, its
     * `attacker_fingerprint` included, in entry order.
     *
     * @param list<BaselineEntry> $entries
     *
     * @return array<string, list<string>>
     */
    private function entryFingerprintsByBaselineFingerprint(array $entries): array
    {
        $entryFingerprints = [];
        foreach ($entries as $entry) {
            foreach ($entry->fingerprints() as $fingerprint) {
                $entryFingerprints[$fingerprint][] = $entry->fingerprint;
            }
        }

        return $entryFingerprints;
    }

    /**
     * One entry per finding `id()`, so two findings sharing a fingerprint keep
     * an entry each.
     *
     * @return list<array<string, string>>
     */
    private function entriesFor(AuditReport $auditReport): array
    {
        $entries = [];
        foreach ($auditReport->vulnerabilities() as $vulnerability) {
            $entries[$vulnerability->id()] = $this->entryFor($vulnerability);
        }

        return array_values($entries);
    }

    /**
     * Adds the `attacker_fingerprint` of a reviewer-corrected finding, which
     * the next run's attacker reports it under.
     *
     * @return array<string, string>
     */
    private function entryFor(Vulnerability $vulnerability): array
    {
        $entry = [
            'fingerprint' => $vulnerability->fingerprint(),
            'type' => $vulnerability->type()->value,
            'file' => $vulnerability->filePath(),
            'title' => $vulnerability->title(),
            'added_at' => $this->clock->now()->format('Y-m-d'),
        ];

        if ($vulnerability->attackerFingerprint() !== $vulnerability->fingerprint()) {
            $entry['attacker_fingerprint'] = $vulnerability->attackerFingerprint();
        }

        return $entry;
    }
}
