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
use Symfony\AI\Platform\Message\Content\Text;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\ProviderMessageRedactor;
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
 * Runs the tool conversations of a concurrency window round by round,
 * dispatching the next call of every pending conversation before resolving
 * any. A conversation still reading on its last round gets one closing
 * request; one that reads again ends as `max_tool_iterations`.
 *
 * A failed call is retried through `RetryingPlatformInvoker`; when every
 * attempt fails transiently, the audit aborts. On any other retry failure, a
 * conversation that ran no tool restarts through completeWithTools(); one
 * that ran a tool rethrows a non-transient failure (never masking it as a
 * SAFE result) and otherwise ends as `empty_content`. A degraded answer is
 * never retried: it ends the conversation as that degraded response. A prompt
 * the model cannot take in ends it as `request_too_large` before any tool
 * ran, as `empty_content` after. A conversation that ran a tool keeps what it
 * recorded. A failure that ends the round cancels the requests in flight.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ToolConversationWavefront
{
    public function __construct(
        private PlatformBinding $platformBinding,
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
        $platform = $this->platformBinding->platform();

        $states = $this->initializeConversationStates($window);

        for ($round = 0; $round <= $maxToolIterations && !ConversationState::allAnswered($states); ++$round) {
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
     * Refuses a round once the budget is spent. Checks it again only after
     * every dispatched conversation is advanced, so each billed call is booked.
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
     * Ends a conversation whose estimate no longer fits the rate-limit window,
     * leaving the others running.
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
     * Cancels every request still open (the failed one's included) and books
     * each but the failed one as spent. A conversation whose dispatch failed
     * only releases its rate-limit reservation.
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
     * Asks a tool call the output cap cut off again with a raised cap, once
     * per conversation; ends the conversation without a retry on any other
     * degraded answer or a prompt the model cannot take in.
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     * @throws NegativeTokenCountException
     */
    private function recoverFailedInvocation(ConversationState $conversationState, Throwable $throwable, ToolLLMRequest $toolLLMRequest, int $maxToolIterations): ConversationState
    {
        $raisedCapState = $this->retryingPlatformInvoker->conversationWithARaisedCap($throwable, $conversationState);
        if ($raisedCapState instanceof ConversationState) {
            return $this->retryOrAbortConversation($raisedCapState, $toolLLMRequest, $maxToolIterations, $throwable);
        }

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
            $callTokens = $this->platformResultExtractor->extractTokens($deferredResult, $conversationState->estimatedInputTokens);
        } catch (Throwable $throwable) {
            $failure = $this->conversionFailureExplainer->explain($throwable, $deferredResult);
            $this->degradedAnswerBooker->bookFailedCall($failure, $deferredResult, $conversationState->estimatedInputTokens);

            throw $failure;
        }

        $conversationState = $conversationState->withRecordedTokens(...$callTokens);
        $this->toolIterationBooker->book($deferredResult, TokenUsageSnapshot::of(...$callTokens));

        if ([] !== $this->platformResultExtractor->extractToolCalls($platformResult)) {
            return $this->runToolCalls($conversationState, $platformResult, $toolLLMRequest);
        }

        return $conversationState->withResponse(FinalRound::settled(LLMResponse::of(
            $this->platformResultExtractor->extractText($platformResult),
            $this->model,
            $this->platformResultExtractor->extractStopReason($deferredResult),
            $conversationState->tokenUsage(),
        ), $conversationState->roundsLeft, $conversationState->askedToRead));
    }

    /**
     * Aborts the audit when every retry attempt fails transiently, the failed
     * dispatch counted. A retry refused as too large ends the conversation
     * without a restart.
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    private function retryOrAbortConversation(ConversationState $conversationState, ToolLLMRequest $toolLLMRequest, int $maxToolIterations, ?Throwable $cutFailure = null): ConversationState
    {
        $retried = $this->retryInvocation($conversationState, $toolLLMRequest, $maxToolIterations, $cutFailure);
        if ($retried instanceof ConversationState) {
            return $retried;
        }

        [$deferredResult, $conversationState] = $retried;

        try {
            return $this->processDeferredResult($conversationState, $deferredResult, $toolLLMRequest);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (Throwable) {
            return $this->abortConversation($conversationState, $toolLLMRequest, $maxToolIterations);
        }
    }

    /**
     * Returns the retried answer with the conversation it continues, or the
     * state the conversation ends in when the retry fails. Checks the budget
     * first; a retry that spends it aborts on the budget.
     *
     * @return array{DeferredResult, ConversationState}|ConversationState
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    private function retryInvocation(ConversationState $conversationState, ToolLLMRequest $toolLLMRequest, int $maxToolIterations, ?Throwable $cutFailure): array|ConversationState
    {
        $this->budgetTracker?->assertWithinBudget();

        try {
            return $this->retryingPlatformInvoker->invokeConversation($conversationState, $cutFailure);
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
     * @throws InvalidTokenUsageException
     */
    private function runToolCalls(ConversationState $conversationState, ResultInterface $platformResult, ToolLLMRequest $toolLLMRequest): ConversationState
    {
        $toolCalls = $this->platformResultExtractor->extractToolCalls($platformResult);
        $conversationState->bag->add($this->platformResultExtractor->extractAssistantMessage($platformResult));

        $toolResults = [];
        foreach ($toolCalls as $position => $toolCall) {
            $result = FinalRound::resultOf($toolLLMRequest->tools, $toolCall, $conversationState->roundsLeft);
            $conversationState->bag->add(new ToolCallMessage($toolCall, new Text(FinalRound::carried($result, $conversationState->roundsLeft, $position === array_key_last($toolCalls)))));
            $toolResults[] = $result;
        }

        $conversationState = $conversationState->withExecutedTools($this->promptTokenEstimator->estimate(...$toolResults), FinalRound::asksToRead($toolLLMRequest->tools, $toolCalls));

        return FinalRound::isConcludedBy($conversationState->roundsLeft, $toolLLMRequest->tools, $toolCalls, $toolResults)
            ? $conversationState->withResponse(FinalRound::answer($this->model, TokenUsageSnapshot::of($conversationState->input, $conversationState->output, $conversationState->cacheRead, $conversationState->cacheCreation), $conversationState->askedToRead))
            : $conversationState;
    }

    /**
     * Restarts a conversation that ran no tool through completeWithTools(). One
     * that ran a tool rethrows a non-transient failure (never masking it as a
     * SAFE result) and otherwise ends as `empty_content`, keeping what it
     * recorded.
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
     * Ends the conversation as the degraded response for an answer cut off,
     * filtered or empty, keeping the tool results it recorded.
     *
     * @throws InvalidTokenUsageException
     */
    private function endDegradedConversation(ConversationState $conversationState, Throwable $throwable, string $stopReason): ConversationState
    {
        $this->logger->warning('Concurrent tool-using conversation ended without usable content; it is answered as a degraded response and keeps the tool results already recorded', [
            'stop_reason' => $stopReason,
            'input_tokens' => $conversationState->input,
            'output_tokens' => $conversationState->output,
            'error' => ProviderMessageRedactor::redact($throwable->getMessage()),
        ]);

        return $conversationState->withResponse(LLMResponse::of(
            '',
            $this->model,
            $stopReason,
            $conversationState->tokenUsage(),
        ));
    }

    /**
     * Before any tool ran, ends the conversation as `request_too_large`,
     * carrying the refusal, so the caller splits the chunk. After a tool ran,
     * ends it as `empty_content`, keeping what it recorded.
     *
     * @throws InvalidTokenUsageException
     */
    private function endOversizedConversation(ConversationState $conversationState, Throwable $throwable): ConversationState
    {
        $tokenUsageSnapshot = $conversationState->tokenUsage();
        $refusal = ProviderMessageRedactor::redact($throwable->getMessage());

        if ($conversationState->toolsRan) {
            $this->logger->warning('Concurrent tool-using conversation outgrew the model input limit after tool results were appended; it ends as an empty response and keeps the tool results already recorded', [
                'input_tokens' => $conversationState->input,
                'output_tokens' => $conversationState->output,
                'error' => $refusal,
            ]);

            return $conversationState->withResponse(LLMResponse::of('', $this->model, 'empty_content', $tokenUsageSnapshot));
        }

        $this->logger->debug('Concurrent tool-using conversation refused as too large for the model before any tool ran; its chunk is handed back to be split', [
            'error' => $refusal,
        ]);

        return $conversationState->withResponse(LLMResponse::of($refusal, $this->model, 'request_too_large', $tokenUsageSnapshot));
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
