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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * Generates and applies the accepted-finding baseline: resolves the effective
 * baseline path (CLI override before the configured default), persists or loads
 * fingerprints via the {@see BaselineInterface}, and filters the report.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BaselineProcessor implements BaselineProcessorInterface
{
    public function __construct(
        private BaselineInterface $baseline,
        private ?string $configuredBaseline = null,
        private ClockInterface $clock = new Clock(),
    ) {}

    #[Override]
    public function generate(AuditReport $auditReport, string $path): int
    {
        $entries = $this->entriesFor($auditReport);
        $this->baseline->save($path, $entries);

        return \count($entries);
    }

    #[Override]
    public function apply(AuditReport $auditReport, ?string $cliBaseline): BaselineResult
    {
        $fingerprints = $this->acceptedFingerprints($cliBaseline);
        if ([] === $fingerprints) {
            return new BaselineResult($auditReport, 0, $fingerprints);
        }

        $before = $auditReport->totalVulnerabilities();
        $filtered = $auditReport->withoutFingerprints($fingerprints);

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

    /**
     * Deduplicates by `fingerprint()` + `attackerFingerprint()` combined —
     * not `fingerprint()` alone — so two distinct findings that happen to
     * share a post-review fingerprint (e.g. one reviewer-corrected onto the
     * same type/file/title as an untouched finding) each keep their own
     * baseline entry instead of one silently overwriting the other's
     * `attacker_fingerprint`.
     *
     * @return list<array<string, string>>
     */
    private function entriesFor(AuditReport $auditReport): array
    {
        $entries = [];
        foreach ($auditReport->vulnerabilities() as $vulnerability) {
            $key = \sprintf('%s|%s', $vulnerability->fingerprint(), $vulnerability->attackerFingerprint());
            $entries[$key] = $this->entryFor($vulnerability);
        }

        return array_values($entries);
    }

    /**
     * A reviewer-corrected finding carries a second, `attacker_fingerprint`
     * key: the identity the attacker will report on the next run, so the
     * pre-review baseline skip still matches it.
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
