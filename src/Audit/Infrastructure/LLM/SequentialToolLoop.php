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
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\ToolCall;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\EmptyLLMResponseException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;

/**
 * Drives one autonomous tool-using conversation sequentially: invokes the
 * platform with retry, executes requested tools against the registry, feeds
 * results back, and returns the model's final textual response — or an
 * empty `max_tool_iterations` response at the iteration cap.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SequentialToolLoop
{
    public function __construct(
        private string $model,
        private LoggerInterface $logger,
        private RateLimiterInterface $rateLimiter,
        private ?BudgetTracker $budgetTracker,
        private RetryingPlatformInvoker $retryingPlatformInvoker,
        private PlatformResultExtractor $platformResultExtractor,
        private PlatformOptionsFactory $platformOptionsFactory,
        private PromptTokenEstimator $promptTokenEstimator,
        private EmptyLLMResponseFactory $emptyLLMResponseFactory,
        private ToolIterationBooker $toolIterationBooker,
    ) {}

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws LLMRequestTooLargeException
     * @throws NonTransientLLMFailureException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function run(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry, int $maxToolIterations): LLMResponse
    {
        \assert('' !== $this->model, 'Model must be a non-empty string');

        $conversationState = $this->openConversation($systemPrompt, $userMessage, $toolRegistry);

        for ($iteration = 0; $iteration < $maxToolIterations; ++$iteration) {
            $this->budgetTracker?->assertWithinBudget();
            $deferredResult = $this->invokeOrEndConversation($conversationState, $iteration);
            if ($deferredResult instanceof LLMResponse) {
                return $deferredResult;
            }

            $platformResult = $deferredResult->getResult();
            $conversationState = $this->bookIteration($conversationState, $deferredResult);
            $toolCalls = $this->platformResultExtractor->extractToolCalls($platformResult);
            if ([] === $toolCalls) {
                return $this->textResponseAndLog($conversationState, $deferredResult, $platformResult, $iteration);
            }

            $roundsLeft = $maxToolIterations - $iteration;
            $conversationState = $this->runToolCalls($conversationState, $toolCalls, $toolRegistry, $iteration, $roundsLeft);
            if (FinalRound::isConcludedBy($roundsLeft, $toolRegistry, ...$toolCalls)) {
                return FinalRound::answer($this->model, $conversationState->tokenUsage());
            }
        }

        return $this->iterationCapResponseAndLog($conversationState, $maxToolIterations);
    }

    private function openConversation(string $systemPrompt, string $userMessage, ToolRegistry $toolRegistry): ConversationState
    {
        $options = $this->platformOptionsFactory->baseOptions();
        $options['tools'] = PlatformToolsMapper::map($toolRegistry->definitions());

        return ConversationState::start(
            new MessageBag(
                Message::forSystem($systemPrompt),
                Message::ofUser($userMessage),
            ),
            $options,
            $this->promptTokenEstimator->estimate($systemPrompt, $userMessage),
        );
    }

    /**
     * Returns the platform's deferred answer, or the response that ends the
     * conversation instead: the model answered with no content, or the
     * conversation outgrew the model after tool results were appended.
     *
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws LLMRequestTooLargeException
     * @throws NonTransientLLMFailureException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws BudgetExceededException
     */
    private function invokeOrEndConversation(ConversationState $conversationState, int $iteration): DeferredResult|LLMResponse
    {
        try {
            return $this->retryingPlatformInvoker->invoke($conversationState->bag, $conversationState->options, $conversationState->estimatedInputTokens);
        } catch (EmptyLLMResponseException $emptyllmResponseException) {
            return $this->emptyToolLoopResponseAndLog($emptyllmResponseException, $iteration, $conversationState->tokenUsage());
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            if (0 === $iteration) {
                throw $llmRequestTooLargeException;
            }

            return $this->outgrownConversationResponseAndLog($llmRequestTooLargeException, $iteration, $conversationState->tokenUsage());
        }
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws BudgetExceededException
     */
    private function bookIteration(ConversationState $conversationState, DeferredResult $deferredResult): ConversationState
    {
        $callTokens = $this->extractCallTokens($deferredResult);
        $this->toolIterationBooker->book($deferredResult, TokenUsageSnapshot::of(...$callTokens));

        return $conversationState->withRecordedTokens(...$callTokens);
    }

    /**
     * @return array{0: int, 1: int, 2: int, 3: int}
     *
     * @throws NegativeTokenCountException
     */
    private function extractCallTokens(DeferredResult $deferredResult): array
    {
        try {
            return $this->platformResultExtractor->extractTokens($deferredResult);
        } catch (Throwable $throwable) {
            $this->rateLimiter->record(0, 0);

            throw $throwable;
        }
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function textResponseAndLog(ConversationState $conversationState, DeferredResult $deferredResult, ResultInterface $platformResult, int $iteration): LLMResponse
    {
        $content = $this->platformResultExtractor->extractText($platformResult);
        $this->logger->debug('Tool-using loop ended with text response', [
            'iterations' => $iteration,
            'content_length' => \strlen($content),
            'input_tokens' => $conversationState->input,
            'output_tokens' => $conversationState->output,
        ]);

        return LLMResponse::of(
            $content,
            $this->model,
            $this->platformResultExtractor->extractStopReason($deferredResult) ?? 'end_turn',
            $conversationState->tokenUsage(),
        );
    }

    /**
     * @param list<ToolCall> $toolCalls
     */
    private function runToolCalls(ConversationState $conversationState, array $toolCalls, ToolRegistry $toolRegistry, int $iteration, int $roundsLeft): ConversationState
    {
        $conversationState->bag->add(new AssistantMessage(...$toolCalls));

        $toolResults = [];
        foreach ($toolCalls as $position => $toolCall) {
            $result = $toolRegistry->execute($toolCall->getName(), $toolCall->getArguments());
            $conversationState->bag->add(new ToolCallMessage($toolCall, new Text(FinalRound::carried($result, $roundsLeft, $position === array_key_last($toolCalls)))));
            $toolResults[] = $result;
            $this->logger->debug('Tool invoked', [
                'tool' => $toolCall->getName(),
                'iteration' => $iteration + 1,
            ]);
        }

        return $conversationState->withExecutedTools($this->promptTokenEstimator->estimate(...$toolResults));
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function iterationCapResponseAndLog(ConversationState $conversationState, int $maxToolIterations): LLMResponse
    {
        $this->logger->warning('Tool-using loop hit iteration cap', [
            'max_iterations' => $maxToolIterations,
            'input_tokens' => $conversationState->input,
            'output_tokens' => $conversationState->output,
        ]);

        return LLMResponse::of('', $this->model, 'max_tool_iterations', $conversationState->tokenUsage());
    }

    private function emptyToolLoopResponseAndLog(
        EmptyLLMResponseException $emptyllmResponseException,
        int $iteration,
        TokenUsageSnapshot $tokenUsageSnapshot,
    ): LLMResponse {
        $context = [
            'iterations' => $iteration,
            'stop_reason' => $emptyllmResponseException->stopReason,
            'input_tokens' => $tokenUsageSnapshot->inputTokens(),
            'output_tokens' => $tokenUsageSnapshot->outputTokens(),
            'error' => $emptyllmResponseException->getMessage(),
        ];

        $this->logEmptyContentResponse($iteration, $context);

        return $this->emptyLLMResponseFactory->create($this->model, $tokenUsageSnapshot, $emptyllmResponseException->stopReason);
    }

    /**
     * The initial prompt fit, so it is the tool results appended since that
     * outgrew the model — splitting the chunk would not change what the model
     * asks to read. The conversation ends here with what it recorded.
     */
    private function outgrownConversationResponseAndLog(
        LLMRequestTooLargeException $llmRequestTooLargeException,
        int $iteration,
        TokenUsageSnapshot $tokenUsageSnapshot,
    ): LLMResponse {
        $this->logger->warning('Tool-using conversation outgrew the model input limit after tool results were appended; it ends as an empty response and keeps the tool results already recorded', [
            'iterations' => $iteration,
            'input_tokens' => $tokenUsageSnapshot->inputTokens(),
            'output_tokens' => $tokenUsageSnapshot->outputTokens(),
            'error' => $llmRequestTooLargeException->getMessage(),
        ]);

        return $this->emptyLLMResponseFactory->create($this->model, $tokenUsageSnapshot);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function logEmptyContentResponse(int $iteration, array $context): void
    {
        if ($iteration > 0) {
            $this->logger->debug('Tool-using loop ended with empty content response', $context);

            return;
        }

        $this->logger->warning('Tool-using loop ended with empty content response', $context);
    }
}
