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
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\ToolCallMessage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\EmptyLLMResponseException;

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
    ) {}

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
            try {
                $deferredResult = $this->retryingPlatformInvoker->invoke($messageBag, $options, $estimatedInputTokens);
            } catch (EmptyLLMResponseException $emptyllmResponseException) {
                return $this->emptyToolLoopResponseAndLog($emptyllmResponseException, $iteration, $totalInputTokens, $totalOutputTokens, $totalCacheReadTokens, $totalCacheCreationTokens);
            }

            $platformResult = $deferredResult->getResult();
            [$callInput, $callOutput, $callCacheRead, $callCacheCreation] = $this->platformResultExtractor->extractTokens($deferredResult);
            $totalInputTokens += $callInput;
            $totalOutputTokens += $callOutput;
            $totalCacheReadTokens += $callCacheRead;
            $totalCacheCreationTokens += $callCacheCreation;
            $this->rateLimiter->record($callInput, $callOutput);
            if ($this->budgetTracker instanceof BudgetTracker) {
                $this->budgetTracker->recordCall(LLMResponse::create(
                    content: '',
                    inputTokens: $callInput,
                    outputTokens: $callOutput,
                    model: $this->model,
                    stopReason: 'tool_iteration',
                    cacheReadTokens: $callCacheRead,
                    cacheCreationTokens: $callCacheCreation,
                ));
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

                return LLMResponse::create(
                    content: $content,
                    inputTokens: $totalInputTokens,
                    outputTokens: $totalOutputTokens,
                    model: $this->model,
                    stopReason: 'end_turn',
                    cacheReadTokens: $totalCacheReadTokens,
                    cacheCreationTokens: $totalCacheCreationTokens,
                );
            }

            $messageBag->add(new AssistantMessage(...$toolCalls));

            foreach ($toolCalls as $toolCall) {
                $result = $toolRegistry->execute($toolCall->getName(), $toolCall->getArguments());
                $messageBag->add(new ToolCallMessage($toolCall, $result));
                $this->logger->debug('Tool invoked', [
                    'tool' => $toolCall->getName(),
                    'iteration' => $iteration + 1,
                ]);
            }

            ++$iteration;
        }

        $this->logger->warning('Tool-using loop hit iteration cap', [
            'max_iterations' => $maxToolIterations,
            'input_tokens' => $totalInputTokens,
            'output_tokens' => $totalOutputTokens,
        ]);

        return LLMResponse::create(
            content: '',
            inputTokens: $totalInputTokens,
            outputTokens: $totalOutputTokens,
            model: $this->model,
            stopReason: 'max_tool_iterations',
            cacheReadTokens: $totalCacheReadTokens,
            cacheCreationTokens: $totalCacheCreationTokens,
        );
    }

    private function emptyToolLoopResponseAndLog(
        EmptyLLMResponseException $emptyllmResponseException,
        int $iteration,
        int $totalInputTokens,
        int $totalOutputTokens,
        int $totalCacheReadTokens,
        int $totalCacheCreationTokens,
    ): LLMResponse {
        $context = [
            'iterations' => $iteration,
            'input_tokens' => $totalInputTokens,
            'output_tokens' => $totalOutputTokens,
            'error' => $emptyllmResponseException->getMessage(),
        ];

        if ($iteration > 0) {
            $this->logger->debug('Tool-using loop ended with empty content response', $context);
        } else {
            $this->logger->warning('Tool-using loop ended with empty content response', $context);
        }

        return LLMResponse::create(
            content: '',
            inputTokens: $totalInputTokens,
            outputTokens: $totalOutputTokens,
            model: $this->model,
            stopReason: 'empty_content',
            cacheReadTokens: $totalCacheReadTokens,
            cacheCreationTokens: $totalCacheCreationTokens,
        );
    }
}
