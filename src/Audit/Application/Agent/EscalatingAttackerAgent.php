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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Two-pass attacker for cost-sensitive audits.
 *
 *   1. A cheap-model attacker (e.g. claude-haiku-4-5) sweeps every chunk.
 *      In typical Symfony projects most files are inert — the cheap sweep
 *      converges quickly with no findings.
 *
 *   2. If the cheap pass found anything, an expensive-model attacker
 *      (e.g. claude-opus-4-7) re-analyses ONLY the files the cheap pass
 *      flagged. Those re-runs benefit from the cheap findings being
 *      injected as previousFindings context, steering the deeper model
 *      at concrete locations to refine / escalate / discover related
 *      issues.
 *
 *   3. The two result sets are merged by Vulnerability::id() (which is
 *      deterministic from type+file+lineStart): the expensive verdict
 *      wins on overlap, cheap findings on cold files pass through.
 *
 * Net effect: full-project coverage at roughly 1/3 to 1/5 of running the
 * expensive model on every chunk, with detection quality close to the
 * pure expensive baseline because hot zones still get the deep treatment.
 */
final readonly class EscalatingAttackerAgent implements AttackerAgentInterface
{
    public function __construct(
        private AttackerAgentInterface $cheapAttacker,
        private AttackerAgentInterface $expensiveAttacker,
        private LoggerInterface $logger,
    ) {}

    public function analyze(array $files, SymfonyMapping $symfonyMapping, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false, array $previousFindings = []): array
    {
        $this->logger->info('Escalation: running cheap-model first pass', [
            'files' => \count($files),
        ]);

        $cheapFindings = $this->cheapAttacker->analyze(
            $files,
            $symfonyMapping,
            $coverageRecorder,
            $bypassCache,
            $previousFindings,
        );

        if ([] === $cheapFindings) {
            $this->logger->info('Escalation: cheap pass found nothing, skipping expensive pass');

            return [];
        }

        $hotFiles = $this->filterToHotFiles($files, $cheapFindings);

        $this->logger->info('Escalation: running expensive-model deep pass on hot files', [
            'cheap_findings' => \count($cheapFindings),
            'hot_files' => \count($hotFiles),
            'cold_files_skipped' => \count($files) - \count($hotFiles),
        ]);

        $expensiveFindings = $this->expensiveAttacker->analyze(
            $hotFiles,
            $symfonyMapping,
            $coverageRecorder,
            $bypassCache,
            [...$previousFindings, ...$cheapFindings],
        );

        return $this->merge($cheapFindings, $expensiveFindings);
    }

    /**
     * @param ProjectFile[]   $files
     * @param Vulnerability[] $cheapFindings
     *
     * @return list<ProjectFile>
     */
    private function filterToHotFiles(array $files, array $cheapFindings): array
    {
        $hotPaths = [];
        foreach ($cheapFindings as $cheapFinding) {
            $hotPaths[$cheapFinding->filePath()] = true;
        }

        return array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => isset($hotPaths[$projectFile->relativePath()]),
        ));
    }

    /**
     * @param Vulnerability[] $cheap
     * @param Vulnerability[] $expensive
     *
     * @return list<Vulnerability>
     */
    private function merge(array $cheap, array $expensive): array
    {
        $byId = [];

        foreach ($expensive as $vulnerability) {
            $byId[$vulnerability->id()] = $vulnerability;
        }

        foreach ($cheap as $vulnerability) {
            if (!isset($byId[$vulnerability->id()])) {
                $byId[$vulnerability->id()] = $vulnerability;
            }
        }

        return array_values($byId);
    }
}
