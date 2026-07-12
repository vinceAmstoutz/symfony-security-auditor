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

use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;

/**
 * Resolves every single-finding review in concurrency windows via the
 * batch-capable client, then applies each verdict. Findings are dispatched one
 * `maxConcurrent`-sized window at a time — never as a single oversized batch —
 * so a budget/provider failure in a later window cannot discard an earlier
 * window's already-applied verdicts; the failing window and every window not
 * yet dispatched are marked `aborted`/`errored` before the exception
 * propagates. Per-finding parse/transient failures degrade to a rejected
 * verdict exactly as the sequential path does. Cached verdicts are served
 * first; only the misses are dispatched.
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
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function analyze(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): array
    {
        $reviewed = [];
        $pending = [];
        $requests = [];
        foreach ($vulnerabilities as $index => $vulnerability) {
            $codeContext = CodeContextResolver::resolve($vulnerability->filePath(), $projectFiles);

            $verdict = $this->servedFromCache($vulnerability, $codeContext, $coverageRecorder, $bypassCache);
            if ($verdict instanceof Vulnerability) {
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
     * Dispatches pending findings one `maxConcurrent`-sized window at a time.
     * Each window is finalized (verdicts applied) as soon as it completes,
     * before the next window is attempted, so a failure partway through never
     * discards an earlier window's completed work.
     *
     * @param list<array{system: string, user: string}>                                        $requests
     * @param list<array{index: int, vulnerability: Vulnerability, cacheContext: string|null}> $pending
     *
     * @return array<int, Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatchPending(array $requests, array $pending, CoverageRecorderInterface $coverageRecorder): array
    {
        if ([] === $requests) {
            return [];
        }

        $windowSize = max(1, $this->maxConcurrent);
        $requestWindows = array_chunk($requests, $windowSize);
        $pendingWindows = array_chunk($pending, $windowSize);

        $reviewed = [];
        foreach ($requestWindows as $windowNumber => $requestWindow) {
            try {
                $reviewed += $this->dispatchWindow($requestWindow, $pendingWindows[$windowNumber], $coverageRecorder);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->failRemainingWindows($pendingWindows, $windowNumber, 'aborted', $coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->failRemainingWindows($pendingWindows, $windowNumber, 'errored', $coverageRecorder);

                throw $llmProviderException;
            }
        }

        return $reviewed;
    }

    /**
     * @param list<array{system: string, user: string}>                                        $requestWindow
     * @param list<array{index: int, vulnerability: Vulnerability, cacheContext: string|null}> $pendingWindow
     *
     * @return array<int, Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatchWindow(array $requestWindow, array $pendingWindow, CoverageRecorderInterface $coverageRecorder): array
    {
        try {
            $responses = $this->batchCapableLLMClient->completeBatch($requestWindow, $this->maxConcurrent);
        } catch (BudgetExceededException|LLMProviderException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            return $this->recordWindowErrors($pendingWindow, $exception, $coverageRecorder);
        }

        $reviewed = [];
        foreach ($pendingWindow as $position => $entry) {
            $reviewed[$entry['index']] = $this->applyResponseOrRecordError($entry, $responses[$position], $coverageRecorder);
        }

        return $reviewed;
    }

    /**
     * @param array{index: int, vulnerability: Vulnerability, cacheContext: string|null} $entry
     */
    private function applyResponseOrRecordError(array $entry, LLMResponse $llmResponse, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        try {
            return $this->reviewOutcomeRecorder->applyResponse($entry['vulnerability'], $llmResponse, $coverageRecorder, $entry['cacheContext']);
        } catch (Throwable $throwable) {
            return $this->reviewOutcomeRecorder->recordReviewError($entry['vulnerability'], $throwable, $coverageRecorder);
        }
    }

    /**
     * @param list<array{index: int, vulnerability: Vulnerability, cacheContext: string|null}> $pendingWindow
     *
     * @return array<int, Vulnerability>
     */
    private function recordWindowErrors(array $pendingWindow, Throwable $throwable, CoverageRecorderInterface $coverageRecorder): array
    {
        $reviewed = [];
        foreach ($pendingWindow as $entry) {
            $reviewed[$entry['index']] = $this->reviewOutcomeRecorder->recordReviewError($entry['vulnerability'], $throwable, $coverageRecorder);
        }

        return $reviewed;
    }

    /**
     * Marks every finding in the window that just failed, plus every window
     * not yet attempted, as failed — without touching windows that already
     * finalized successfully.
     *
     * @param list<list<array{index: int, vulnerability: Vulnerability, cacheContext: string|null}>> $pendingWindows
     */
    private function failRemainingWindows(array $pendingWindows, int $fromWindowNumber, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($pendingWindows as $windowNumber => $window) {
            if ($windowNumber < $fromWindowNumber) {
                continue;
            }

            foreach ($window as $entry) {
                $this->reviewOutcomeRecorder->recordUnreached($entry['vulnerability'], $status, $coverageRecorder);
            }
        }
    }
}
