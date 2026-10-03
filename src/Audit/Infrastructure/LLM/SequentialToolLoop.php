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

        $messageBag = new MessageBag(
            Message::forSystem($systemPrompt),
            Message::ofUser($userMessage),
        );

        $options = $this->platformOptionsFactory->baseOptions();
        $options['tools'] = PlatformToolsMapper::map($toolRegistry->definitions());

        $estimatedInputTokens = $this->promptTokenEstimator->estimate($systemPrompt, $userMessage);

        $iteration = 0;
        $totalInputTokens = 0;
        $totalOutputTokens = 0;
        $totalCacheReadTokens = 0;
        $totalCacheCreationTokens = 0;
        while ($iteration < $maxToolIterations) {
            $this->budgetTracker?->assertWithinBudget();
            $deferredResult = $this->invokeOrEndConversation($messageBag, $options, $estimatedInputTokens, $iteration, TokenUsageSnapshot::of($totalInputTokens, $totalOutputTokens, $totalCacheReadTokens, $totalCacheCreationTokens));
            if ($deferredResult instanceof LLMResponse) {
                return $deferredResult;
            }

            $platformResult = $deferredResult->getResult();
            try {
                [$callInput, $callOutput, $callCacheRead, $callCacheCreation] = $this->platformResultExtractor->extractTokens($deferredResult);
            } catch (Throwable $throwable) {
                $this->rateLimiter->record(0, 0);

                throw $throwable;
            }

            $totalInputTokens += $callInput;
            $totalOutputTokens += $callOutput;
            $totalCacheReadTokens += $callCacheRead;
            $totalCacheCreationTokens += $callCacheCreation;
            $this->rateLimiter->record($callInput, $callOutput);
            if ($this->budgetTracker instanceof BudgetTracker) {
                $this->budgetTracker->recordCall(LLMResponse::of(
                    '',
                    $this->model,
                    'tool_iteration',
                    TokenUsageSnapshot::of($callInput, $callOutput, $callCacheRead, $callCacheCreation),
                )->withReportedModel($this->platformResultExtractor->extractReportedModel($deferredResult)));
                $this->budgetTracker->assertWithinBudget();
            }

            $toolCalls = $this->platformResultExtractor->extractToolCalls($platformResult);

            if ([] === $toolCalls) {
                $content = $this->platformResultExtractor->extractText($platformResult);
                $this->logger->debug('Tool-using loop ended with text response', [
                    'iterations' => $iteration,
                    'content_length' => \strlen($content),
                    'input_tokens' => $totalInputTokens,
                    'output_tokens' => $totalOutputTokens,
                ]);

                return LLMResponse::of(
                    $content,
                    $this->model,
                    $this->platformResultExtractor->extractStopReason($deferredResult) ?? 'end_turn',
                    TokenUsageSnapshot::of($totalInputTokens, $totalOutputTokens, $totalCacheReadTokens, $totalCacheCreationTokens),
                );
            }

            $messageBag->add(new AssistantMessage(...$toolCalls));

            $toolResults = [];
            foreach ($toolCalls as $toolCall) {
                $result = $toolRegistry->execute($toolCall->getName(), $toolCall->getArguments());
                $messageBag->add(new ToolCallMessage($toolCall, new Text($result)));
                $toolResults[] = $result;
                $this->logger->debug('Tool invoked', [
                    'tool' => $toolCall->getName(),
                    'iteration' => $iteration + 1,
                ]);
            }

            $estimatedInputTokens += $this->promptTokenEstimator->estimate(...$toolResults);

            ++$iteration;
        }

        $this->logger->warning('Tool-using loop hit iteration cap', [
            'max_iterations' => $maxToolIterations,
            'input_tokens' => $totalInputTokens,
            'output_tokens' => $totalOutputTokens,
        ]);

        return LLMResponse::of(
            '',
            $this->model,
            'max_tool_iterations',
            TokenUsageSnapshot::of($totalInputTokens, $totalOutputTokens, $totalCacheReadTokens, $totalCacheCreationTokens),
        );
    }

    /**
     * Returns the platform's deferred answer, or the response that ends the
     * conversation instead: the model answered with no content, or the
     * conversation outgrew the model after tool results were appended.
     *
     * @param array<string, mixed> $options
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
    private function invokeOrEndConversation(MessageBag $messageBag, array $options, int $estimatedInputTokens, int $iteration, TokenUsageSnapshot $tokenUsageSnapshot): DeferredResult|LLMResponse
    {
        try {
            return $this->retryingPlatformInvoker->invoke($messageBag, $options, $estimatedInputTokens);
        } catch (EmptyLLMResponseException $emptyllmResponseException) {
            return $this->emptyToolLoopResponseAndLog($emptyllmResponseException, $iteration, $tokenUsageSnapshot);
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            if (0 === $iteration) {
                throw $llmRequestTooLargeException;
            }

            return $this->outgrownConversationResponseAndLog($llmRequestTooLargeException, $iteration, $tokenUsageSnapshot);
        }
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
