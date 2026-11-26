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

use Closure;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordReviewToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * Sends several review batches in one call of a client that takes several
 * requests and reads each answer as the answer of a batch sent alone.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ConcurrentReviewWindow
{
    public function __construct(
        private LLMClientInterface $llmClient,
        private ReviewerPromptBuilderInterface $reviewerPromptBuilder,
        private BatchAnswerReader $batchAnswerReader,
        private BatchVerdictApplier $batchVerdictApplier,
        private OversizedReviewBatchRecovery $oversizedReviewBatchRecovery,
        private LoggerInterface $logger,
        private int $maxToolIterations,
        private ?RecordReviewToolFactoryInterface $recordReviewToolFactory,
    ) {}

    /**
     * How many batches go out at once: `maxConcurrent` to a client that takes
     * several requests in the mode of the review, without tools, one
     * otherwise.
     *
     * @return int<1, max>
     */
    public function size(ReviewBatchSettings $reviewBatchSettings): int
    {
        $takesSeveral = $reviewBatchSettings->structured
            ? $this->llmClient instanceof ToolBatchCapableLLMClientInterface
            : $this->llmClient instanceof BatchCapableLLMClientInterface;

        return $takesSeveral && !$reviewBatchSettings->toolRegistry instanceof ToolRegistry ? $reviewBatchSettings->maxConcurrent : 1;
    }

    /**
     * Sends the batches of a window in one call. A budget or provider failure
     * of that call keeps the verdicts recorded before it, marks the other
     * findings of the window `aborted` or `errored` and propagates.
     *
     * @param list<list<Vulnerability>>                         $window
     * @param Closure(list<Vulnerability>): list<Vulnerability> $reviewBatchAlone reviews a half of a batch the model could not take in whole
     *
     * @return list<list<Vulnerability>>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function review(array $window, ReviewCacheBuckets $reviewCacheBuckets, ReviewBatchSettings $reviewBatchSettings, Closure $reviewBatchAlone): array
    {
        $coverageRecorder = $reviewBatchSettings->coverageRecorder;
        $sessions = $reviewBatchSettings->structured ? $this->sessionsFor($window) : [];

        try {
            $responses = $this->dispatch($window, $sessions, $reviewCacheBuckets->codeContexts, $reviewBatchSettings->maxConcurrent);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->stop($window, $sessions, $reviewCacheBuckets->cacheContexts, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->stop($window, $sessions, $reviewCacheBuckets->cacheContexts, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (Throwable $exception) {
            return array_map(
                fn (array $batch, int $position): array => $this->batchAnswerReader->recordDrainedBatchOrError($batch, $sessions[$position] ?? null, $reviewCacheBuckets->cacheContexts, $exception, $coverageRecorder),
                $window,
                array_keys($window),
            );
        }

        $windowReviewed = $this->readAnswers($window, $responses, $sessions, $reviewCacheBuckets->cacheContexts, $coverageRecorder)
            + $this->splitOversized($window, $responses, $coverageRecorder, $reviewBatchAlone);
        ksort($windowReviewed);

        return array_values($windowReviewed);
    }

    /**
     * @param list<list<Vulnerability>> $window
     *
     * @return list<StructuredReviewCollectionSession>
     *
     * @throws InvalidToolRegistryException
     */
    private function sessionsFor(array $window): array
    {
        \assert($this->recordReviewToolFactory instanceof RecordReviewToolFactoryInterface);

        return array_map(fn (): StructuredReviewCollectionSession => StructuredReviewCollectionSession::begin($this->recordReviewToolFactory, $this->logger), $window);
    }

    /**
     * @param list<list<Vulnerability>>               $window
     * @param list<StructuredReviewCollectionSession> $sessions     one per batch, none when the review reads JSON
     * @param array<string, string>                   $codeContexts
     *
     * @return list<LLMResponse>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatch(array $window, array $sessions, array $codeContexts, int $maxConcurrent): array
    {
        $requests = array_map(
            fn (array $batch): array => ['system' => $this->reviewerPromptBuilder->buildBatchSystemPrompt(), 'user' => $this->reviewerPromptBuilder->buildBatchUserMessage($batch, $codeContexts)],
            $window,
        );

        if ([] === $sessions && $this->llmClient instanceof BatchCapableLLMClientInterface) {
            return $this->llmClient->completeBatch($requests, $maxConcurrent);
        }

        \assert($this->llmClient instanceof ToolBatchCapableLLMClientInterface);

        return $this->llmClient->completeBatchWithTools(
            array_map(static fn (array $request, StructuredReviewCollectionSession $structuredReviewCollectionSession): array => [...$request, 'tools' => $structuredReviewCollectionSession->toolRegistry], $requests, $sessions),
            $maxConcurrent,
            $this->maxToolIterations,
        );
    }

    /**
     * @param list<list<Vulnerability>>               $window
     * @param list<StructuredReviewCollectionSession> $sessions
     * @param array<string, string>                   $cacheContexts
     */
    private function stop(array $window, array $sessions, array $cacheContexts, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($window as $position => $batch) {
            $this->batchAnswerReader->recordDrainedBatchOrMarkUnreached($batch, $sessions[$position] ?? null, $cacheContexts, $status, $coverageRecorder);
        }
    }

    /**
     * Reads every answer of the window but those the model refused as too
     * large. A failure to read one records its batch as an error alone.
     *
     * @param list<list<Vulnerability>>               $window
     * @param list<LLMResponse>                       $responses
     * @param list<StructuredReviewCollectionSession> $sessions
     * @param array<string, string>                   $cacheContexts
     *
     * @return array<int, list<Vulnerability>> keyed by position in the window
     */
    private function readAnswers(array $window, array $responses, array $sessions, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
    {
        $windowReviewed = [];
        foreach ($responses as $position => $llmResponse) {
            if (!$llmResponse->isRequestTooLarge()) {
                $windowReviewed[$position] = $this->readAnswer($window[$position], $llmResponse, $sessions[$position] ?? null, $cacheContexts, $coverageRecorder);
            }
        }

        return $windowReviewed;
    }

    /**
     * @param list<Vulnerability>   $batch
     * @param array<string, string> $cacheContexts
     *
     * @return list<Vulnerability>
     */
    private function readAnswer(array $batch, LLMResponse $llmResponse, ?StructuredReviewCollectionSession $structuredReviewCollectionSession, array $cacheContexts, CoverageRecorderInterface $coverageRecorder): array
    {
        try {
            return $structuredReviewCollectionSession instanceof StructuredReviewCollectionSession
                ? $this->batchAnswerReader->readStructuredBatchAnswer($batch, $llmResponse, $structuredReviewCollectionSession, $cacheContexts, $coverageRecorder)
                : $this->batchAnswerReader->readBatchAnswer($batch, $llmResponse, $cacheContexts, $coverageRecorder);
        } catch (Throwable $throwable) {
            return $this->batchAnswerReader->recordDrainedBatchOrError($batch, $structuredReviewCollectionSession, $cacheContexts, $throwable, $coverageRecorder);
        }
    }

    /**
     * Splits the batches the model refused as too large one after another.
     * An abort while splitting one marks those after it unreached.
     *
     * @param list<list<Vulnerability>>                         $window
     * @param list<LLMResponse>                                 $responses
     * @param Closure(list<Vulnerability>): list<Vulnerability> $reviewBatchAlone
     *
     * @return array<int, list<Vulnerability>> keyed by position in the window
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function splitOversized(array $window, array $responses, CoverageRecorderInterface $coverageRecorder, Closure $reviewBatchAlone): array
    {
        $oversized = array_keys(array_filter($responses, static fn (LLMResponse $llmResponse): bool => $llmResponse->isRequestTooLarge()));

        $windowReviewed = [];
        foreach ($oversized as $number => $position) {
            try {
                $windowReviewed[$position] = $this->oversizedReviewBatchRecovery->recover($window[$position], new LLMRequestTooLargeException($responses[$position]->content()), $coverageRecorder, $reviewBatchAlone);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->markUnreached($window, \array_slice($oversized, $number + 1), 'aborted', $coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->markUnreached($window, \array_slice($oversized, $number + 1), 'errored', $coverageRecorder);

                throw $llmProviderException;
            }
        }

        return $windowReviewed;
    }

    /**
     * @param list<list<Vulnerability>> $window
     * @param list<int>                 $positions
     */
    private function markUnreached(array $window, array $positions, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($positions as $position) {
            $this->batchVerdictApplier->markBatchUnreached($window[$position], $status, $coverageRecorder);
        }
    }
}
