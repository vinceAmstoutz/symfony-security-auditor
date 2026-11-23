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
 * Reviews the cache-miss findings one by one through the batch-capable
 * client, one `maxConcurrent`-sized window at a time. A budget or provider
 * failure keeps the verdicts of earlier windows and marks the failing window
 * and the ones after it `aborted` or `errored` before propagating. A parse or
 * transient failure on one finding degrades as in the sequential path.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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

            $pending[] = new PendingReview($index, $vulnerability, $bypassCache ? null : $codeContext);
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
     * Applies each window's verdicts before dispatching the next.
     *
     * @param list<array{system: string, user: string}> $requests
     * @param list<PendingReview>                       $pending
     *
     * @return array<int, Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatchPending(array $requests, array $pending, CoverageRecorderInterface $coverageRecorder): array
    {
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
     * @param list<array{system: string, user: string}> $requestWindow
     * @param list<PendingReview>                       $pendingWindow
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
        foreach ($pendingWindow as $position => $pendingReview) {
            $reviewed[$pendingReview->index] = $this->applyResponseOrRecordError($pendingReview, $responses[$position], $coverageRecorder);
        }

        return $reviewed;
    }

    private function applyResponseOrRecordError(PendingReview $pendingReview, LLMResponse $llmResponse, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        try {
            return $this->reviewOutcomeRecorder->applyResponse($pendingReview->vulnerability, $llmResponse, $coverageRecorder, $pendingReview->cacheContext);
        } catch (Throwable $throwable) {
            return $this->reviewOutcomeRecorder->recordReviewError($pendingReview->vulnerability, $throwable, $coverageRecorder);
        }
    }

    /**
     * @param list<PendingReview> $pendingWindow
     *
     * @return array<int, Vulnerability>
     */
    private function recordWindowErrors(array $pendingWindow, Throwable $throwable, CoverageRecorderInterface $coverageRecorder): array
    {
        $reviewed = [];
        foreach ($pendingWindow as $pendingReview) {
            $reviewed[$pendingReview->index] = $this->reviewOutcomeRecorder->recordReviewError($pendingReview->vulnerability, $throwable, $coverageRecorder);
        }

        return $reviewed;
    }

    /**
     * Marks the findings of the failed window and of every later window as
     * `$status`.
     *
     * @param list<list<PendingReview>> $pendingWindows
     */
    private function failRemainingWindows(array $pendingWindows, int $fromWindowNumber, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($pendingWindows as $windowNumber => $window) {
            if ($windowNumber < $fromWindowNumber) {
                continue;
            }

            foreach ($window as $pendingReview) {
                $this->reviewOutcomeRecorder->recordUnreached($pendingReview->vulnerability, $status, $coverageRecorder);
            }
        }
    }
}
