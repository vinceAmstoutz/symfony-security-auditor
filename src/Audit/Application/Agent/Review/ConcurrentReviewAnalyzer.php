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
        $pending = [];
        $requests = [];
        foreach ($vulnerabilities as $index => $vulnerability) {
            $codeContext = CodeContextResolver::resolve($vulnerability->filePath(), $projectFiles);

            $verdict = $this->servedFromCache($vulnerability, $codeContext, $coverageRecorder, $bypassCache);
            if (null !== $verdict) {
                $reviewed[$index] = $verdict;

                continue;
            }

            $pending[] = [
                'index' => $index,
                'vulnerability' => $vulnerability,
                'cacheContext' => $bypassCache ? null : $codeContext,
            ];
            $requests[] = $this->buildRequest($vulnerability, $codeContext);
        }

        foreach ($this->dispatchPending($requests, $pending, $coverageRecorder) as $index => $verdict) {
            $reviewed[$index] = $verdict;
        }

        ksort($reviewed);

        return array_values($reviewed);
    }

    private function servedFromCache(Vulnerability $vulnerability, string $codeContext, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): ?Vulnerability
    {
        $cached = $this->reviewerVerdictCache->get($vulnerability, $codeContext, $bypassCache);
        if (null === $cached) {
            return null;
        }

        return $this->reviewOutcomeRecorder->recordVerdict($vulnerability, $cached, $coverageRecorder);
    }

    /**
     * @return array{system: string, user: string}
     */
    private function buildRequest(Vulnerability $vulnerability, string $codeContext): array
    {
        return [
            'system' => $this->reviewerPromptBuilder->buildSystemPrompt(),
            'user' => $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext),
        ];
    }

    /**
     * @param list<array{system: string, user: string}>                          $requests
     * @param list<array{index: int, vulnerability: Vulnerability, cacheContext: string|null}> $pending
     *
     * @return array<int, Vulnerability>
     */
    private function dispatchPending(array $requests, array $pending, CoverageRecorderInterface $coverageRecorder): array
    {
        if ([] === $requests) {
            return [];
        }

        $responses = $this->batchCapableLLMClient->completeBatch($requests, $this->maxConcurrent);
        $reviewed = [];
        foreach ($pending as $position => $entry) {
            $reviewed[$entry['index']] = $this->reviewOutcomeRecorder->applyResponse($entry['vulnerability'], $responses[$position], $coverageRecorder, $entry['cacheContext']);
        }

        return $reviewed;
    }
}
