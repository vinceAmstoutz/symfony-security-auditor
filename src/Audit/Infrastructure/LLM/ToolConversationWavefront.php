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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Psr\Log\LoggerInterface;
use Symfony\AI\Platform\Message\AssistantMessage;
use Symfony\AI\Platform\Message\Content\Text;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\ToolCall;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolLLMRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\EmptyLLMResponseException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;

/**
 * Runs every tool-using conversation in a concurrency window as a wavefront:
 * each round dispatches the next platform invocation for every still-pending
 * conversation WITHOUT blocking, then resolves them, executes the requested
 * tools against that conversation's own registry, and queues the follow-up
 * round. On an async transport (the symfony/ai DeferredResult contract) the
 * per-round invocations overlap on the wire. Any dispatch or resolution
 * failure first retries the same conversation through
 * `RetryingPlatformInvoker` — the same classify-then-retry-or-fail seam the
 * sequential path uses — once the budget allows another call. When every
 * attempt of that retry fails transiently, the audit aborts as it does on the
 * sequential path, under an attempt count that includes the dispatch. When the
 * retry fails otherwise, a conversation that hasn't run a tool yet falls back
 * to the proven sequential completeWithTools() path (full restart). One that
 * already ran a tool cannot restart without executing it twice: a failure
 * classified non-transient is rethrown instead of masked, per the LLM seam's
 * contract that non-transient provider failures must never be swallowed into
 * a false-negative SAFE result, and anything else finalizes it as an empty
 * `empty_content` response.
 *
 * An answer with nothing usable in it — empty, cut off by the output limit or
 * withheld by a content filter — is never retried or restarted either: the
 * conversation ends as the matching degraded response.
 *
 * A prompt the model cannot take in is never retried or restarted: before any
 * tool ran, the conversation ends as a `request_too_large` response the
 * caller splits the work on; after a tool ran, as an `empty_content` response
 * that keeps what it recorded. A failure that does end the round cancels the
 * requests still in flight, so their HTTP responses neither wait for the
 * provider in their destructors nor replace the failure with their own.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ToolConversationWavefront
{
    public function __construct(
        private ?PlatformInterface $platform,
        private string $model,
        private LoggerInterface $logger,
        private RateLimiterInterface $rateLimiter,
        private ?BudgetTracker $budgetTracker,
        private PlatformResultExtractor $platformResultExtractor,
        private PlatformOptionsFactory $platformOptionsFactory,
        private PromptTokenEstimator $promptTokenEstimator,
        private LLMClientInterface $llmClient,
        private RetryingPlatformInvoker $retryingPlatformInvoker,
        private TransientFailureClassifier $transientFailureClassifier,
        private InFlightRequestCanceller $inFlightRequestCanceller,
        private DegradedAnswerBooker $degradedAnswerBooker,
        private ConversionFailureExplainer $conversionFailureExplainer,
        private ToolIterationBooker $toolIterationBooker,
    ) {}

    /**
     * @param list<ToolLLMRequest> $window
     *
     * @return list<LLMResponse>
     *
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     * @throws NegativeTokenCountException
     */
    public function resolveToolWindow(array $window, int $maxToolIterations): array
    {
        $platform = $this->platform ?? throw MissingAiPlatformException::create();

        $states = $this->initializeConversationStates($window);

        for ($round = 0; $round < $maxToolIterations && !ConversationState::allAnswered($states); ++$round) {
            $states = ConversationState::enterRound($states, $round, $maxToolIterations);
            $states = $this->runWavefrontRound($platform, $states, $window, $maxToolIterations);
        }

        return $this->collectResponses($states, $maxToolIterations);
    }

    /**
     * @param list<ToolLLMRequest> $window
     *
     * @return array<int, ConversationState>
     */
    private function initializeConversationStates(array $window): array
    {
        $states = [];
        foreach ($window as $index => $toolLLMRequest) {
            $options = $this->platformOptionsFactory->baseOptions();
            $options['tools'] = PlatformToolsMapper::map($toolLLMRequest->tools->definitions());
            $states[$index] = ConversationState::start(
                new MessageBag(Message::forSystem($toolLLMRequest->system), Message::ofUser($toolLLMRequest->user)),
                $options,
                $this->promptTokenEstimator->estimate($toolLLMRequest->system, $toolLLMRequest->user),
            );
        }

        return $states;
    }

    /**
     * Refuses to dispatch a round once the budget is spent, and gives the
     * budget verdict only after every conversation the round did dispatch has
     * been advanced — each was billed by the provider, so its spend belongs on
     * the books before the abort, not just the first one's.
     *
     * @param array<int, ConversationState> $states
     * @param list<ToolLLMRequest>          $window
     *
     * @return array<int, ConversationState>
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     * @throws NegativeTokenCountException
     */
    private function runWavefrontRound(PlatformInterface $platform, array $states, array $window, int $maxToolIterations): array
    {
        $this->budgetTracker?->assertWithinBudget();
        [$states, $dispatched] = $this->dispatchPendingInvocations($platform, $states);
        $states = $this->advanceDispatched($states, $dispatched, $window, $maxToolIterations);
        $this->budgetTracker?->assertWithinBudget();

        return $states;
    }

    /**
     * A conversation whose estimate no longer fits the rate-limit window ends
     * on the spot instead of taking the whole window down with it.
     *
     * @param array<int, ConversationState> $states
     *
     * @return array{0: array<int, ConversationState>, 1: array<int, DeferredResult|Throwable>}
     *
     * @throws InvalidTokenUsageException
     */
    private function dispatchPendingInvocations(PlatformInterface $platform, array $states): array
    {
        $dispatched = [];
        foreach ($states as $index => $conversationState) {
            if ($conversationState->response instanceof LLMResponse) {
                continue;
            }

            try {
                $this->rateLimiter->acquire($conversationState->estimatedInputTokens);
            } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
                $states[$index] = $this->endOversizedConversation($conversationState, $llmRequestTooLargeException);

                continue;
            }

            $dispatched[$index] = $this->invokeWithoutThrowing($platform, $conversationState->bag, $conversationState->options);
        }

        return [$states, $dispatched];
    }

    /**
     * @param array<string, mixed> $options
     */
    private function invokeWithoutThrowing(PlatformInterface $platform, MessageBag $messageBag, array $options): DeferredResult|Throwable
    {
        \assert('' !== $this->model, 'Model must be a non-empty string');

        try {
            return $platform->invoke($this->model, $messageBag, $options);
        } catch (Throwable $throwable) {
            return $throwable;
        }
    }

    /**
     * @param array<int, ConversationState>        $states
     * @param array<int, DeferredResult|Throwable> $dispatched
     * @param list<ToolLLMRequest>                 $window
     *
     * @return array<int, ConversationState>
     *
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     * @throws NegativeTokenCountException
     */
    private function advanceDispatched(array $states, array $dispatched, array $window, int $maxToolIterations): array
    {
        $unconsumed = $dispatched;

        foreach ($dispatched as $index => $outcome) {
            try {
                $states[$index] = $this->advanceConversation($states[$index], $outcome, $window[$index], $maxToolIterations);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->logger->debug('Budget exceeded while advancing a concurrent conversation; the remaining dispatched conversations of the round are still resolved so their spend is recorded', [
                    'error' => $budgetExceededException->getMessage(),
                ]);
            } catch (Throwable $throwable) {
                $this->cancelUnconsumed($unconsumed, $states, $index);

                throw $throwable;
            }

            unset($unconsumed[$index]);
        }

        return $states;
    }

    /**
     * Every in-flight request left open is cancelled — including the
     * conversation whose own advance threw, whose HTTP handle may still be
     * open — and booked as spent. The conversation that threw is not booked:
     * it was read to completion (its real usage is already recorded) or it
     * errored before generating anything. A conversation whose dispatch failed
     * never reached the provider: only its rate-limit reservation is released.
     *
     * @param array<int, DeferredResult|Throwable> $unconsumed
     * @param array<int, ConversationState>        $states
     *
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    private function cancelUnconsumed(array $unconsumed, array $states, int $consumedFailedIndex): void
    {
        $open = [];
        foreach ($unconsumed as $index => $outcome) {
            $open[$index] = [$outcome instanceof DeferredResult ? $outcome : null, $states[$index]->estimatedInputTokens];
        }

        $this->inFlightRequestCanceller->cancelAll($open, $consumedFailedIndex);
    }

    /**
     * @param array<int, ConversationState> $states
     *
     * @return list<LLMResponse>
     *
     * @throws InvalidTokenUsageException
     */
    private function collectResponses(array $states, int $maxToolIterations): array
    {
        $responses = [];
        foreach ($states as $state) {
            $responses[] = $state->response ?? $this->toolIterationCapResponse($state, $maxToolIterations);
        }

        return $responses;
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     * @throws NegativeTokenCountException
     */
    private function advanceConversation(ConversationState $conversationState, DeferredResult|Throwable $dispatched, ToolLLMRequest $toolLLMRequest, int $maxToolIterations): ConversationState
    {
        if ($dispatched instanceof Throwable) {
            $this->degradedAnswerBooker->bookFailedCall($dispatched, null, $conversationState->estimatedInputTokens);

            return $this->recoverFailedInvocation($conversationState, $dispatched, $toolLLMRequest, $maxToolIterations);
        }

        try {
            return $this->processDeferredResult($conversationState, $dispatched, $toolLLMRequest);
        } catch (Throwable $throwable) {
            return $this->recoverFailedInvocation($conversationState, $throwable, $toolLLMRequest, $maxToolIterations);
        }
    }

    /**
     * A prompt the model cannot take in is not worth a retry or a restart —
     * the same prompt is refused again — so it ends the conversation at once.
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     * @throws NegativeTokenCountException
     */
    private function recoverFailedInvocation(ConversationState $conversationState, Throwable $throwable, ToolLLMRequest $toolLLMRequest, int $maxToolIterations): ConversationState
    {
        $degradedStopReason = $this->transientFailureClassifier->degradedStopReason($throwable);
        if (null !== $degradedStopReason) {
            return $this->endDegradedConversation($conversationState, $throwable, $degradedStopReason);
        }

        if ($this->transientFailureClassifier->isRequestTooLarge($throwable)) {
            return $this->endOversizedConversation($conversationState, $throwable);
        }

        return $this->retryOrAbortConversation($conversationState, $toolLLMRequest, $maxToolIterations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     */
    private function processDeferredResult(ConversationState $conversationState, DeferredResult $deferredResult, ToolLLMRequest $toolLLMRequest): ConversationState
    {
        try {
            $platformResult = $deferredResult->getResult();
            $callTokens = $this->platformResultExtractor->extractTokens($deferredResult);
        } catch (Throwable $throwable) {
            $failure = $this->conversionFailureExplainer->explain($throwable, $deferredResult);
            $this->degradedAnswerBooker->bookFailedCall($failure, $deferredResult, $conversationState->estimatedInputTokens);

            throw $failure;
        }

        $conversationState = $conversationState->withRecordedTokens(...$callTokens);
        $this->toolIterationBooker->book($deferredResult, TokenUsageSnapshot::of(...$callTokens));

        $toolCalls = $this->platformResultExtractor->extractToolCalls($platformResult);

        if ([] !== $toolCalls) {
            return $this->runToolCalls($conversationState, $toolCalls, $toolLLMRequest);
        }

        return $conversationState->withResponse(LLMResponse::of(
            $this->platformResultExtractor->extractText($platformResult),
            $this->model,
            $this->platformResultExtractor->extractStopReason($deferredResult) ?? 'end_turn',
            $conversationState->tokenUsage(),
        ));
    }

    /**
     * Retries a failed dispatch/resolution through the same
     * classify-then-retry-or-fail seam the sequential path uses. A retry whose
     * attempts all fail transiently aborts the audit, as the sequential path
     * does, counting the dispatch that failed first. A retry that fails
     * otherwise goes to `abortConversation()`, and a retry the model refuses
     * as too large ends the conversation without the restart, which would
     * only send the same prompt a third time.
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    private function retryOrAbortConversation(ConversationState $conversationState, ToolLLMRequest $toolLLMRequest, int $maxToolIterations): ConversationState
    {
        $retried = $this->retryInvocation($conversationState, $toolLLMRequest, $maxToolIterations);
        if ($retried instanceof ConversationState) {
            return $retried;
        }

        try {
            return $this->processDeferredResult($conversationState, $retried, $toolLLMRequest);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (Throwable) {
            return $this->abortConversation($conversationState, $toolLLMRequest, $maxToolIterations);
        }
    }

    /**
     * The retried answer, or the state the conversation ends in when the
     * retry itself fails. The conversation's own answer, or a sibling advanced
     * earlier in the round, may have spent the budget, so it is checked before
     * the retry is dispatched; a retry whose billed attempts spend it aborts
     * on the budget too, rather than ending the conversation as one that
     * failed.
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    private function retryInvocation(ConversationState $conversationState, ToolLLMRequest $toolLLMRequest, int $maxToolIterations): DeferredResult|ConversationState
    {
        $this->budgetTracker?->assertWithinBudget();

        try {
            return $this->retryingPlatformInvoker->invoke($conversationState->bag, $conversationState->options, $conversationState->estimatedInputTokens);
        } catch (EmptyLLMResponseException $emptyLLMResponseException) {
            return $this->endDegradedConversation($conversationState, $emptyLLMResponseException, $emptyLLMResponseException->stopReason);
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            return $this->endOversizedConversation($conversationState, $llmRequestTooLargeException);
        } catch (TransientLLMFailureException $transientLLMFailureException) {
            throw $transientLLMFailureException->afterOneMoreAttempt();
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (Throwable $throwable) {
            return $this->abortConversation($conversationState, $toolLLMRequest, $maxToolIterations, $throwable);
        }
    }

    /**
     * @param list<ToolCall> $toolCalls
     *
     * @throws InvalidTokenUsageException
     */
    private function runToolCalls(ConversationState $conversationState, array $toolCalls, ToolLLMRequest $toolLLMRequest): ConversationState
    {
        $conversationState->bag->add(new AssistantMessage(...$toolCalls));

        $toolResults = [];
        foreach ($toolCalls as $position => $toolCall) {
            $result = $toolLLMRequest->tools->execute($toolCall->getName(), $toolCall->getArguments());
            $conversationState->bag->add(new ToolCallMessage($toolCall, new Text(FinalRound::carried($result, $conversationState->roundsLeft, $position === array_key_last($toolCalls)))));
            $toolResults[] = $result;
        }

        $conversationState = $conversationState->withExecutedTools($this->promptTokenEstimator->estimate(...$toolResults));

        return FinalRound::isConcludedBy($conversationState->roundsLeft, $toolLLMRequest->tools, ...$toolCalls)
            ? $conversationState->withResponse(FinalRound::answer($this->model, TokenUsageSnapshot::of($conversationState->input, $conversationState->output, $conversationState->cacheRead, $conversationState->cacheCreation)))
            : $conversationState;
    }

    /**
     * A conversation that cannot go on. Before any tool ran it restarts from
     * scratch through completeWithTools(). After one ran it cannot restart
     * without executing that tool a second time: a failure classified
     * non-transient is rethrown, since finalizing it would mask a failure that
     * repeats on every call behind a false-negative SAFE result, and anything
     * else ends the conversation as `empty_content`, keeping what it recorded.
     *
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     */
    private function abortConversation(ConversationState $conversationState, ToolLLMRequest $toolLLMRequest, int $maxToolIterations, ?Throwable $throwable = null): ConversationState
    {
        if (!$conversationState->toolsRan) {
            return $this->restartConversation($conversationState, $toolLLMRequest, $maxToolIterations);
        }

        return $this->keepRecordedToolResults($conversationState, $throwable);
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function restartConversation(ConversationState $conversationState, ToolLLMRequest $toolLLMRequest, int $maxToolIterations): ConversationState
    {
        try {
            return $conversationState->withResponse($this->llmClient->completeWithTools($toolLLMRequest->system, $toolLLMRequest->user, $toolLLMRequest->tools, $maxToolIterations));
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            return $this->endOversizedConversation($conversationState, $llmRequestTooLargeException);
        }
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     */
    private function keepRecordedToolResults(ConversationState $conversationState, ?Throwable $throwable): ConversationState
    {
        if ($throwable instanceof NonTransientLLMFailureException) {
            throw $throwable;
        }

        $this->logger->warning('Concurrent tool-using conversation failed after tool execution; keeping recorded tool results', [
            'input_tokens' => $conversationState->input,
            'output_tokens' => $conversationState->output,
        ]);

        return $conversationState->withResponse(LLMResponse::of(
            '',
            $this->model,
            'empty_content',
            $conversationState->tokenUsage(),
        ));
    }

    /**
     * The model answered, but with nothing usable — cut off by the output
     * limit, withheld by a content filter, or empty. Asking again would get the
     * same answer at the same price, so the conversation ends as the degraded
     * response the sequential path returns for it, keeping any tool results it
     * already recorded.
     *
     * @throws InvalidTokenUsageException
     */
    private function endDegradedConversation(ConversationState $conversationState, Throwable $throwable, string $stopReason): ConversationState
    {
        $this->logger->warning('Concurrent tool-using conversation ended without usable content; it is answered as a degraded response and keeps the tool results already recorded', [
            'stop_reason' => $stopReason,
            'input_tokens' => $conversationState->input,
            'output_tokens' => $conversationState->output,
            'error' => $throwable->getMessage(),
        ]);

        return $conversationState->withResponse(LLMResponse::of(
            '',
            $this->model,
            $stopReason,
            $conversationState->tokenUsage(),
        ));
    }

    /**
     * Before any tool ran, the refusal is the caller's to act on — the
     * `request_too_large` response carries it as content, and the chunk it
     * stands for gets split. After a tool ran it is the tool results that
     * outgrew the model, which splitting the chunk would not change, so the
     * conversation ends with what it recorded.
     *
     * @throws InvalidTokenUsageException
     */
    private function endOversizedConversation(ConversationState $conversationState, Throwable $throwable): ConversationState
    {
        $tokenUsageSnapshot = $conversationState->tokenUsage();

        if ($conversationState->toolsRan) {
            $this->logger->warning('Concurrent tool-using conversation outgrew the model input limit after tool results were appended; it ends as an empty response and keeps the tool results already recorded', [
                'input_tokens' => $conversationState->input,
                'output_tokens' => $conversationState->output,
                'error' => $throwable->getMessage(),
            ]);

            return $conversationState->withResponse(LLMResponse::of('', $this->model, 'empty_content', $tokenUsageSnapshot));
        }

        $this->logger->debug('Concurrent tool-using conversation refused as too large for the model before any tool ran; its chunk is handed back to be split', [
            'error' => $throwable->getMessage(),
        ]);

        return $conversationState->withResponse(LLMResponse::of($throwable->getMessage(), $this->model, 'request_too_large', $tokenUsageSnapshot));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function toolIterationCapResponse(ConversationState $conversationState, int $maxToolIterations): LLMResponse
    {
        $this->logger->warning('Tool-using loop hit iteration cap', [
            'max_iterations' => $maxToolIterations,
            'input_tokens' => $conversationState->input,
            'output_tokens' => $conversationState->output,
        ]);

        return LLMResponse::of('', $this->model, 'max_tool_iterations', $conversationState->tokenUsage());
    }
}
