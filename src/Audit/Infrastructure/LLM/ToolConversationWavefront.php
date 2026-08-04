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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;

/**
 * Runs every tool-using conversation in a concurrency window as a wavefront:
 * each round dispatches the next platform invocation for every still-pending
 * conversation WITHOUT blocking, then resolves them, executes the requested
 * tools against that conversation's own registry, and queues the follow-up
 * round. On an async transport (the symfony/ai DeferredResult contract) the
 * per-round invocations overlap on the wire. Any dispatch or resolution
 * failure first retries the same conversation through
 * `RetryingPlatformInvoker` — the same classify-then-retry-or-fail seam the
 * sequential path uses. Once that retry gives up, a conversation that hasn't
 * run a tool yet always falls back to the proven sequential
 * completeWithTools() path (full restart) — safe to retry from scratch
 * regardless of why the retry failed. One that already ran a tool cannot
 * restart without executing it twice, so it finalizes as an empty
 * `empty_content` response instead — unless the retry's own failure was
 * classified non-transient, which is rethrown instead of masked, per the LLM
 * seam's contract that non-transient provider failures must never be
 * swallowed into a false-negative SAFE result.
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
    ) {}

    /**
     * @param list<array{system: string, user: string, tools: ToolRegistry}> $window
     *
     * @return list<LLMResponse>
     *
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     */
    public function resolveToolWindow(array $window, int $maxToolIterations): array
    {
        $platform = $this->platform ?? throw MissingAiPlatformException::create();

        $states = $this->initializeConversationStates($window);

        for ($round = 0; $round < $maxToolIterations; ++$round) {
            $states = $this->runWavefrontRound($platform, $states, $window, $maxToolIterations);
        }

        return $this->collectResponses($states, $maxToolIterations);
    }

    /**
     * @param list<array{system: string, user: string, tools: ToolRegistry}> $window
     *
     * @return array<int, ConversationState>
     */
    private function initializeConversationStates(array $window): array
    {
        $states = [];
        foreach ($window as $index => $request) {
            $options = $this->platformOptionsFactory->baseOptions();
            $options['tools'] = PlatformToolsMapper::map($request['tools']->definitions());
            $states[$index] = new ConversationState(
                new MessageBag(Message::forSystem($request['system']), Message::ofUser($request['user'])),
                $options,
                0,
                0,
                0,
                0,
                false,
                null,
                $this->promptTokenEstimator->estimate($request['system'], $request['user']),
            );
        }

        return $states;
    }

    /**
     * @param array<int, ConversationState>                                  $states
     * @param list<array{system: string, user: string, tools: ToolRegistry}> $window
     *
     * @return array<int, ConversationState>
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     */
    private function runWavefrontRound(PlatformInterface $platform, array $states, array $window, int $maxToolIterations): array
    {
        $deferred = $this->dispatchPendingInvocations($platform, $states);

        foreach ($deferred as $index => $deferredResult) {
            $states[$index] = $this->advanceConversation($states[$index], $deferredResult, $window[$index], $maxToolIterations);
        }

        return $states;
    }

    /**
     * @param array<int, ConversationState> $states
     *
     * @return array<int, DeferredResult|null>
     */
    private function dispatchPendingInvocations(PlatformInterface $platform, array $states): array
    {
        $deferred = [];
        foreach ($states as $index => $conversationState) {
            if ($conversationState->response instanceof LLMResponse) {
                continue;
            }

            $this->rateLimiter->acquire($conversationState->estimatedInputTokens);

            $deferred[$index] = $this->invokeWithoutThrowing($platform, $conversationState->bag, $conversationState->options);
        }

        return $deferred;
    }

    /**
     * @param array<string, mixed> $options
     */
    private function invokeWithoutThrowing(PlatformInterface $platform, MessageBag $messageBag, array $options): ?DeferredResult
    {
        \assert('' !== $this->model, 'Model must be a non-empty string');

        try {
            return $platform->invoke($this->model, $messageBag, $options);
        } catch (Throwable) {
            return null;
        }
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
            $responses[] = $state->response instanceof LLMResponse
                ? $state->response
                : $this->toolIterationCapResponse($state, $maxToolIterations);
        }

        return $responses;
    }

    /**
     * @param array{system: string, user: string, tools: ToolRegistry} $request
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     */
    private function advanceConversation(ConversationState $conversationState, ?DeferredResult $deferredResult, array $request, int $maxToolIterations): ConversationState
    {
        if (!$deferredResult instanceof DeferredResult) {
            $this->rateLimiter->record(0, 0);

            return $this->retryOrAbortConversation($conversationState, $request, $maxToolIterations);
        }

        try {
            return $this->processDeferredResult($conversationState, $deferredResult, $request);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (Throwable) {
            return $this->retryOrAbortConversation($conversationState, $request, $maxToolIterations);
        }
    }

    /**
     * @param array{system: string, user: string, tools: ToolRegistry} $request
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     */
    private function processDeferredResult(ConversationState $conversationState, DeferredResult $deferredResult, array $request): ConversationState
    {
        try {
            $platformResult = $deferredResult->getResult();
            [$callInput, $callOutput, $callCacheRead, $callCacheCreation] = $this->platformResultExtractor->extractTokens($deferredResult);
        } catch (Throwable $throwable) {
            $this->rateLimiter->record(0, 0);

            throw $throwable;
        }

        $conversationState = $conversationState->withRecordedTokens($callInput, $callOutput, $callCacheRead, $callCacheCreation);
        $this->rateLimiter->record($callInput, $callOutput);
        if ($this->budgetTracker instanceof BudgetTracker) {
            $this->budgetTracker->recordCall(LLMResponse::of(
                '',
                $this->model,
                'tool_iteration',
                TokenUsageSnapshot::of($callInput, $callOutput, $callCacheRead, $callCacheCreation),
            ));
            $this->budgetTracker->assertWithinBudget();
        }

        $toolCalls = $this->platformResultExtractor->extractToolCalls($platformResult);

        if ([] !== $toolCalls) {
            return $this->runToolCalls($conversationState, $toolCalls, $request);
        }

        return $conversationState->withResponse(LLMResponse::of(
            $this->platformResultExtractor->extractText($platformResult),
            $this->model,
            $this->platformResultExtractor->extractStopReason($deferredResult) ?? 'end_turn',
            TokenUsageSnapshot::of($conversationState->input, $conversationState->output, $conversationState->cacheRead, $conversationState->cacheCreation),
        ));
    }

    /**
     * Retries a failed dispatch/resolution through the same
     * classify-then-retry-or-fail seam the sequential path uses. Falls back to
     * `abortConversation()` once that retry itself fails — which restarts
     * from scratch via completeWithTools() for a conversation that hasn't run
     * a tool yet, or finalizes as `empty_content` for one that has (it cannot
     * restart without executing that tool a second time). The one exception:
     * a tool-ran conversation whose retry failure is classified non-transient
     * is rethrown rather than finalized, since a restart can't happen and
     * masking the failure would produce a false-negative SAFE result.
     *
     * @param array{system: string, user: string, tools: ToolRegistry} $request
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     */
    private function retryOrAbortConversation(ConversationState $conversationState, array $request, int $maxToolIterations): ConversationState
    {
        try {
            $deferredResult = $this->retryingPlatformInvoker->invoke($conversationState->bag, $conversationState->options, $conversationState->estimatedInputTokens);
        } catch (NonTransientLLMFailureException $nonTransientLLMFailureException) {
            if ($conversationState->toolsRan) {
                throw $nonTransientLLMFailureException;
            }

            return $this->abortConversation($conversationState, $request, $maxToolIterations);
        } catch (Throwable) {
            return $this->abortConversation($conversationState, $request, $maxToolIterations);
        }

        try {
            return $this->processDeferredResult($conversationState, $deferredResult, $request);
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (Throwable) {
            return $this->abortConversation($conversationState, $request, $maxToolIterations);
        }
    }

    /**
     * @param list<ToolCall>                                           $toolCalls
     * @param array{system: string, user: string, tools: ToolRegistry} $request
     */
    private function runToolCalls(ConversationState $conversationState, array $toolCalls, array $request): ConversationState
    {
        $conversationState->bag->add(new AssistantMessage(...$toolCalls));

        $toolResults = [];
        foreach ($toolCalls as $toolCall) {
            $result = $request['tools']->execute($toolCall->getName(), $toolCall->getArguments());
            $conversationState->bag->add(new ToolCallMessage($toolCall, new Text($result)));
            $toolResults[] = $result;
        }

        return $conversationState->withExecutedTools($this->promptTokenEstimator->estimate(...$toolResults));
    }

    /**
     * @param array{system: string, user: string, tools: ToolRegistry} $request
     *
     * @throws InvalidTokenUsageException
     */
    private function abortConversation(ConversationState $conversationState, array $request, int $maxToolIterations): ConversationState
    {
        if (!$conversationState->toolsRan) {
            return $conversationState->withResponse($this->llmClient->completeWithTools($request['system'], $request['user'], $request['tools'], $maxToolIterations));
        }

        $this->logger->warning('Concurrent tool-using conversation failed after tool execution; keeping recorded tool results', [
            'input_tokens' => $conversationState->input,
            'output_tokens' => $conversationState->output,
        ]);

        return $conversationState->withResponse(LLMResponse::of(
            '',
            $this->model,
            'empty_content',
            TokenUsageSnapshot::of($conversationState->input, $conversationState->output, $conversationState->cacheRead, $conversationState->cacheCreation),
        ));
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

        return LLMResponse::of(
            '',
            $this->model,
            'max_tool_iterations',
            TokenUsageSnapshot::of($conversationState->input, $conversationState->output, $conversationState->cacheRead, $conversationState->cacheCreation),
        );
    }
}
