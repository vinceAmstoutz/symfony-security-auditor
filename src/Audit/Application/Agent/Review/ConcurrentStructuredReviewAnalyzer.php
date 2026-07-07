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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * Resolves every single-finding review in concurrency windows via the
 * tool-batch-capable client, each verdict arriving through its own
 * schema-enforced `record_review` tool. Pending findings are dispatched one
 * `maxConcurrent`-sized window at a time — never as a single oversized batch —
 * so a budget/provider failure in a later window cannot discard an earlier
 * window's already-applied verdicts; the failing window and every window not
 * yet dispatched are marked `aborted`/`errored` before the exception
 * propagates. Cached verdicts are served first; only the misses are
 * dispatched.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
            $concurrentReviewBatch = new ConcurrentReviewBatch($requests, $pendingIndexes, $sessions, $vulnerabilities, $codeContexts);
            $reviewed = $this->dispatchInWindows($concurrentReviewBatch, $bypassCache, $coverageRecorder, $reviewed);
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
     * Dispatches pending findings one `maxConcurrent`-sized window at a time.
     * Each window is finalized (verdicts applied) as soon as it completes,
     * before the next window is attempted, so a failure partway through never
     * discards an earlier window's completed work.
     *
     * @param array<int, Vulnerability> $reviewed
     *
     * @return array<int, Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatchInWindows(ConcurrentReviewBatch $concurrentReviewBatch, bool $bypassCache, CoverageRecorderInterface $coverageRecorder, array $reviewed): array
    {
        $windowSize = max(1, $this->maxConcurrent);
        $requestWindows = array_chunk($concurrentReviewBatch->requests, $windowSize);
        $indexWindows = array_chunk($concurrentReviewBatch->pendingIndexes, $windowSize);

        foreach ($requestWindows as $windowNumber => $requestWindow) {
            $windowBatch = new ConcurrentReviewBatch($requestWindow, $indexWindows[$windowNumber], $concurrentReviewBatch->sessions, $concurrentReviewBatch->vulnerabilities, $concurrentReviewBatch->codeContexts);

            try {
                $reviewed = $this->dispatchPending($windowBatch, $coverageRecorder, $bypassCache, $reviewed);
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
     * Marks every finding in the window that just failed, plus every window
     * not yet attempted, as failed — without touching windows that already
     * finalized successfully. A finding whose `record_review` tool call
     * already landed in an earlier round of the same failed window's batch
     * call keeps its verdict instead of being marked unreached.
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
                $vulnerability = $concurrentReviewBatch->vulnerabilities[$index];
                $recovered = $this->reviewOutcomeRecorder->recoverDrainedVerdict($vulnerability, $concurrentReviewBatch->sessions[$index], $coverageRecorder);
                if (!$recovered instanceof Vulnerability) {
                    $this->reviewOutcomeRecorder->recordUnreached($vulnerability, $status, $coverageRecorder);
                }
            }
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
    private function dispatchPending(ConcurrentReviewBatch $concurrentReviewBatch, CoverageRecorderInterface $coverageRecorder, bool $bypassCache, array $reviewed): array
    {
        try {
            $this->toolBatchCapableLLMClient->completeBatchWithTools($concurrentReviewBatch->requests, $this->maxConcurrent, $this->maxToolIterations);

            foreach ($concurrentReviewBatch->pendingIndexes as $index) {
                $reviewed[$index] = $this->recordPendingVerdict($index, $concurrentReviewBatch, $coverageRecorder, $bypassCache);
            }

            return $reviewed;
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            throw $llmProviderException;
        } catch (Throwable $exception) {
            return $this->recordPendingErrors($concurrentReviewBatch, $exception, $coverageRecorder, $reviewed);
        }
    }

    private function recordPendingVerdict(int $index, ConcurrentReviewBatch $concurrentReviewBatch, CoverageRecorderInterface $coverageRecorder, bool $bypassCache): Vulnerability
    {
        $verdicts = $concurrentReviewBatch->sessions[$index]->drain();
        $verdict = array_pop($verdicts);
        if (!$bypassCache) {
            $this->reviewerVerdictCache->store($concurrentReviewBatch->vulnerabilities[$index], $concurrentReviewBatch->codeContexts[$index], $verdict);
        }

        return $this->reviewOutcomeRecorder->recordVerdict($concurrentReviewBatch->vulnerabilities[$index], $verdict, $coverageRecorder);
    }

    /**
     * A finding whose `record_review` tool call already landed in an earlier
     * round of this same window's batch call keeps its verdict instead of
     * being overwritten as errored — mirrors the recovery
     * `failRemainingWindows()` already applies for a Budget/LLMProviderException
     * abort, extended to every other `Throwable` this window's dispatch can
     * throw.
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
        $recovered = $this->reviewOutcomeRecorder->recoverDrainedVerdict($vulnerability, $concurrentReviewBatch->sessions[$index], $coverageRecorder);

        return $recovered ?? $this->reviewOutcomeRecorder->recordReviewError($vulnerability, $throwable, $coverageRecorder);
    }
}
