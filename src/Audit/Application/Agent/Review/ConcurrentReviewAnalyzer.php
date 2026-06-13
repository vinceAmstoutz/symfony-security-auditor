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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;

/**
 * Resolves every single-finding review in concurrency windows via the
 * batch-capable client, then applies each verdict. Budget and non-transient
 * provider failures propagate (the batch client rethrows them); per-finding
 * parse/transient failures degrade to a rejected verdict exactly as the
 * sequential path does. Cached verdicts are served first; only the misses are
 * dispatched.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConcurrentReviewAnalyzer
{
    public function __construct(
        private BatchCapableLLMClientInterface $batchCapableLLMClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private ReviewOutcomeRecorder $reviewOutcomeRecorder,
        private int $maxConcurrent,
    ) {}

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     */
    public function analyze(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): array
    {
        $reviewed = [];
        $codeContexts = [];
        $pendingIndexes = [];
        $requests = [];
        foreach ($vulnerabilities as $index => $vulnerability) {
            $codeContext = CodeContextResolver::resolve($vulnerability->filePath(), $projectFiles);
            $codeContexts[$index] = $codeContext;

            $cached = $this->reviewerVerdictCache->get($vulnerability, $codeContext, $bypassCache);
            if (null !== $cached) {
                $reviewed[$index] = $this->reviewOutcomeRecorder->recordVerdict($vulnerability, $cached, $coverageRecorder);

                continue;
            }

            $pendingIndexes[] = $index;
            $requests[] = [
                'system' => $this->reviewerPromptBuilder->buildSystemPrompt(),
                'user' => $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext),
            ];
        }

        if ([] !== $requests) {
            $responses = $this->batchCapableLLMClient->completeBatch($requests, $this->maxConcurrent);
            foreach ($pendingIndexes as $position => $index) {
                $reviewed[$index] = $this->reviewOutcomeRecorder->applyResponse($vulnerabilities[$index], $responses[$position], $coverageRecorder, $bypassCache ? null : $codeContexts[$index]);
            }
        }

        ksort($reviewed);

        return array_values($reviewed);
    }
}
