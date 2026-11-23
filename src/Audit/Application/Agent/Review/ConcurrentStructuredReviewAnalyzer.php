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

use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordingToolClients;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * Reviews the cache-miss findings one by one through the tool-batch-capable
 * client, each verdict through its own `record_review` tool, one
 * `maxConcurrent`-sized window at a time. A budget or provider failure keeps
 * the verdicts of earlier windows and marks the failing window and the ones
 * after it `aborted` or `errored` before propagating.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConcurrentStructuredReviewAnalyzer
{
    public function __construct(
        private ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private ReviewerVerdictCache $reviewerVerdictCache,
        private ReviewOutcomeRecorder $reviewOutcomeRecorder,
        private RecordReviewToolFactoryInterface $recordReviewToolFactory,
        private LoggerInterface $logger,
        private int $maxConcurrent,
        private int $maxToolIterations,
        private RecordingToolClients $recordingToolClients,
    ) {}

    /**
     * @param list<Vulnerability> $vulnerabilities
     * @param list<ProjectFile>   $projectFiles
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function analyze(array $vulnerabilities, array $projectFiles, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): array
    {
        $reviewed = [];
        $codeContexts = [];
        $sessions = [];
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

            $structuredReviewCollectionSession = StructuredReviewCollectionSession::begin($this->recordReviewToolFactory, $this->logger);
            $sessions[$index] = $structuredReviewCollectionSession;
            $pendingIndexes[] = $index;
            $requests[] = $this->buildRequest($vulnerability, $codeContext, $structuredReviewCollectionSession);
        }

        if ([] !== $requests) {
            $concurrentReviewBatch = new ConcurrentReviewBatch($requests, $pendingIndexes, $sessions, $vulnerabilities, $codeContexts, $bypassCache);
            $reviewed = $this->dispatchInWindows($concurrentReviewBatch, $coverageRecorder, $reviewed);
        }

        ksort($reviewed);

        return array_values($reviewed);
    }

    /**
     * @return array{system: string, user: string, tools: ToolRegistry}
     */
    private function buildRequest(Vulnerability $vulnerability, string $codeContext, StructuredReviewCollectionSession $structuredReviewCollectionSession): array
    {
        return [
            'system' => $this->reviewerPromptBuilder->buildSystemPrompt(),
            'user' => $this->reviewerPromptBuilder->buildUserMessage($vulnerability, $codeContext),
            'tools' => $structuredReviewCollectionSession->toolRegistry,
        ];
    }

    /**
     * Applies each window's verdicts before dispatching the next.
     *
     * @param array<int, Vulnerability> $reviewed
     *
     * @return array<int, Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatchInWindows(ConcurrentReviewBatch $concurrentReviewBatch, CoverageRecorderInterface $coverageRecorder, array $reviewed): array
    {
        $windowSize = max(1, $this->maxConcurrent);
        $requestWindows = array_chunk($concurrentReviewBatch->requests, $windowSize);
        $indexWindows = array_chunk($concurrentReviewBatch->pendingIndexes, $windowSize);

        foreach ($requestWindows as $windowNumber => $requestWindow) {
            $windowBatch = new ConcurrentReviewBatch($requestWindow, $indexWindows[$windowNumber], $concurrentReviewBatch->sessions, $concurrentReviewBatch->vulnerabilities, $concurrentReviewBatch->codeContexts, $concurrentReviewBatch->bypassCache);

            try {
                $reviewed = $this->dispatchPending($windowBatch, $coverageRecorder, $reviewed);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->failRemainingWindows($indexWindows, $windowNumber, $concurrentReviewBatch, 'aborted', $coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->failRemainingWindows($indexWindows, $windowNumber, $concurrentReviewBatch, 'errored', $coverageRecorder);

                throw $llmProviderException;
            }
        }

        return $reviewed;
    }

    /**
     * Marks the findings of the failed window and of every later window as
     * `$status`, except a finding whose verdict was recorded before the
     * failure, which keeps it.
     *
     * @param list<list<int>> $indexWindows
     */
    private function failRemainingWindows(array $indexWindows, int $fromWindowNumber, ConcurrentReviewBatch $concurrentReviewBatch, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($indexWindows as $windowNumber => $indexes) {
            if ($windowNumber < $fromWindowNumber) {
                continue;
            }

            foreach ($indexes as $index) {
                $this->recordUnreachedUnlessRecovered($index, $concurrentReviewBatch, $status, $coverageRecorder);
            }
        }
    }

    private function recordUnreachedUnlessRecovered(int $index, ConcurrentReviewBatch $concurrentReviewBatch, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        $vulnerability = $concurrentReviewBatch->vulnerabilities[$index];
        $recovered = $this->reviewOutcomeRecorder->recoverDrainedVerdict($vulnerability, $concurrentReviewBatch->sessions[$index], $coverageRecorder, $concurrentReviewBatch->codeContextForCache($index));
        if (!$recovered instanceof Vulnerability) {
            $this->reviewOutcomeRecorder->recordUnreached($vulnerability, $status, $coverageRecorder);
        }
    }

    /**
     * @param array<int, Vulnerability> $reviewed
     *
     * @return array<int, Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatchPending(ConcurrentReviewBatch $concurrentReviewBatch, CoverageRecorderInterface $coverageRecorder, array $reviewed): array
    {
        try {
            $responses = $this->toolBatchCapableLLMClient->completeBatchWithTools($concurrentReviewBatch->requests, $this->maxConcurrent, $this->maxToolIterations);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->recordPendingErrors($concurrentReviewBatch, $exception, $coverageRecorder, $reviewed);
        }

        $this->noteRecordingToolReach($concurrentReviewBatch);
        foreach ($concurrentReviewBatch->pendingIndexes as $position => $index) {
            $reviewed[$index] = $this->recordPendingVerdictOrError($index, $responses[$position], $concurrentReviewBatch, $coverageRecorder);
        }

        return $reviewed;
    }

    /**
     * A client that offered the recording tool to one request of the window
     * offered it to all of them, though it may have built the schemas once.
     */
    private function noteRecordingToolReach(ConcurrentReviewBatch $concurrentReviewBatch): void
    {
        foreach ($concurrentReviewBatch->pendingIndexes as $index) {
            $this->recordingToolClients->note($this->toolBatchCapableLLMClient, $concurrentReviewBatch->sessions[$index]->recordingToolReached());
        }
    }

    private function recordPendingVerdictOrError(int $index, LLMResponse $llmResponse, ConcurrentReviewBatch $concurrentReviewBatch, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        try {
            return $this->recordPendingVerdict($index, $llmResponse, $concurrentReviewBatch, $coverageRecorder);
        } catch (Throwable $throwable) {
            return $this->recoveredOrErroredVerdict($index, $concurrentReviewBatch, $throwable, $coverageRecorder);
        }
    }

    /**
     * Records a finding errored and uncached, never rejected, when a degraded
     * answer holds no verdict for it. Applies a verdict recorded before the
     * cut-off. Reads the JSON answer when the client never offered the
     * tool.
     */
    private function recordPendingVerdict(int $index, LLMResponse $llmResponse, ConcurrentReviewBatch $concurrentReviewBatch, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        if ($this->recordingToolClients->ignoresTools($this->toolBatchCapableLLMClient)) {
            return $this->reviewOutcomeRecorder->applyResponse($concurrentReviewBatch->vulnerabilities[$index], $llmResponse, $coverageRecorder, $concurrentReviewBatch->codeContextForCache($index));
        }

        $verdicts = $concurrentReviewBatch->sessions[$index]->drain();
        $verdict = array_pop($verdicts);
        if (null === $verdict && $llmResponse->isDegraded()) {
            return $this->reviewOutcomeRecorder->recordIncompleteResponse($concurrentReviewBatch->vulnerabilities[$index], $llmResponse, $coverageRecorder);
        }

        $cacheContext = ReviewerVerdictCache::contextFor($llmResponse, $concurrentReviewBatch->codeContextForCache($index));
        if (null !== $cacheContext) {
            $this->reviewerVerdictCache->store($concurrentReviewBatch->vulnerabilities[$index], $cacheContext, $verdict);
        }

        return $this->reviewOutcomeRecorder->recordVerdict($concurrentReviewBatch->vulnerabilities[$index], $verdict, $coverageRecorder, $llmResponse->reachedToolCap());
    }

    /**
     * Marks the window's findings errored, except a finding whose verdict was
     * recorded before the failure, which keeps it.
     *
     * @param array<int, Vulnerability> $reviewed
     *
     * @return array<int, Vulnerability>
     */
    private function recordPendingErrors(ConcurrentReviewBatch $concurrentReviewBatch, Throwable $throwable, CoverageRecorderInterface $coverageRecorder, array $reviewed): array
    {
        foreach ($concurrentReviewBatch->pendingIndexes as $pendingIndex) {
            $reviewed[$pendingIndex] = $this->recoveredOrErroredVerdict($pendingIndex, $concurrentReviewBatch, $throwable, $coverageRecorder);
        }

        return $reviewed;
    }

    private function recoveredOrErroredVerdict(int $index, ConcurrentReviewBatch $concurrentReviewBatch, Throwable $throwable, CoverageRecorderInterface $coverageRecorder): Vulnerability
    {
        $vulnerability = $concurrentReviewBatch->vulnerabilities[$index];
        $recovered = $this->reviewOutcomeRecorder->recoverDrainedVerdict($vulnerability, $concurrentReviewBatch->sessions[$index], $coverageRecorder, $concurrentReviewBatch->codeContextForCache($index));

        return $recovered ?? $this->reviewOutcomeRecorder->recordReviewError($vulnerability, $throwable, $coverageRecorder);
    }
}
