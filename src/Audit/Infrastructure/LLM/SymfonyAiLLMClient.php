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

use DateTimeImmutable;
use Psr\Log\LoggerInterface;
use Symfony\AI\Platform\Message\AssistantMessage;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\MultiPartResult;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\TokenUsage\TokenUsageInterface;
use Symfony\AI\Platform\Tool\ExecutionReference;
use Symfony\AI\Platform\Tool\Tool;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\EmptyLLMResponseException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SymfonyAiLLMClient implements BatchCapableLLMClientInterface
{
    public const ?float DEFAULT_TEMPERATURE = null;

    public const bool DEFAULT_PROVIDER_JSON_MODE = false;

    public const ?int DEFAULT_MAX_OUTPUT_TOKENS = null;

    public function __construct(
        private ?PlatformInterface $platform,
        private string $model,
        private LoggerInterface $logger,
        private ?float $temperature = self::DEFAULT_TEMPERATURE,
        private ?TokenUsageRecorder $tokenUsageRecorder = null,
        private ?RetryPolicy $retryPolicy = null,
        private ?TransientFailureClassifier $transientFailureClassifier = null,
        private ?SleeperInterface $sleeper = null,
        private ?BudgetTracker $budgetTracker = null,
        private bool $providerJsonMode = self::DEFAULT_PROVIDER_JSON_MODE,
        private ?RateLimiterInterface $rateLimiter = null,
        private ?TokenEstimatorInterface $tokenEstimator = null,
        private ?RetryAfterHeaderParser $retryAfterHeaderParser = null,
        private ?int $maxOutputTokens = self::DEFAULT_MAX_OUTPUT_TOKENS,
    ) {}

    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        $this->logger->debug('Invoking symfony/ai platform', [
            'system_length' => \strlen($systemPrompt),
            'user_length' => \strlen($userMessage),
            'temperature' => $this->temperature,
        ]);

        $messageBag = new MessageBag(
            Message::forSystem($systemPrompt),
            Message::ofUser($userMessage),
        );

        \assert('' !== $this->model, 'Model must be a non-empty string');

        $estimatedInputTokens = $this->estimateInputTokens($systemPrompt, $userMessage);
        try {
            $deferredResult = $this->invokeWithRetry($messageBag, $this->baseOptions(), $estimatedInputTokens);
        } catch (EmptyLLMResponseException $emptyllmResponseException) {
            return $this->emptyResponseAndLog($emptyllmResponseException);
        }

        $content = $deferredResult->asText();
        [$inputTokens, $outputTokens] = $this->extractTokens($deferredResult);

        $this->rateLimiter()->record($inputTokens, $outputTokens);

        $this->logger->debug('symfony/ai platform responded', [
            'content_length' => \strlen($content),
            'input_tokens' => $inputTokens,
            'output_tokens' => $outputTokens,
        ]);

        $llmResponse = LLMResponse::create(
            content: $content,
            inputTokens: $inputTokens,
            outputTokens: $outputTokens,
            model: $this->model,
            stopReason: 'end_turn',
        );
        $this->budgetTracker?->recordCall($llmResponse);
        $this->budgetTracker?->assertWithinBudget();

        return $llmResponse;
    }

    public function completeBatch(array $requests, int $maxConcurrent): array
    {
        \assert('' !== $this->model, 'Model must be a non-empty string');

        $windowSize = max(1, $maxConcurrent);
        $responses = [];

        foreach (array_chunk($requests, $windowSize) as $window) {
            foreach ($this->resolveWindow($window) as $llmResponse) {
                $responses[] = $llmResponse;
            }
        }

        return $responses;
    }

    /**
     * Dispatches every request in the window via the platform WITHOUT blocking,
     * then resolves them. When the platform's transport is async (the symfony/ai
     * DeferredResult contract), the resolutions overlap on the wire. Any request
     * that fails to dispatch or resolve falls back to the proven sequential
     * complete() path (full retry) so the batch path is never less correct than
     * the per-call path.
     *
     * @param list<array{system: string, user: string}> $window
     *
     * @return list<LLMResponse>
     */
    private function resolveWindow(array $window): array
    {
        \assert('' !== $this->model, 'Model must be a non-empty string');

        $platform = $this->platform();
        $deferred = [];
        foreach ($window as $index => $request) {
            $messageBag = new MessageBag(
                Message::forSystem($request['system']),
                Message::ofUser($request['user']),
            );
            $estimatedInputTokens = $this->estimateInputTokens($request['system'], $request['user']);
            $this->rateLimiter()->acquire($estimatedInputTokens);

            try {
                $deferred[$index] = $platform->invoke($this->model, $messageBag, $this->baseOptions());
            } catch (Throwable) {
                $deferred[$index] = null;
            }
        }

        $resolved = [];
        foreach ($window as $index => $request) {
            $resolved[$index] = $this->resolveOne($deferred[$index], $request);
        }

        return array_values($resolved);
    }

    /**
     * @param array{system: string, user: string} $request
     */
    private function resolveOne(?DeferredResult $deferredResult, array $request): LLMResponse
    {
        if (!$deferredResult instanceof DeferredResult) {
            return $this->complete($request['system'], $request['user']);
        }

        try {
            $content = $deferredResult->asText();
            [$inputTokens, $outputTokens] = $this->extractTokens($deferredResult);
            $this->rateLimiter()->record($inputTokens, $outputTokens);

            $llmResponse = LLMResponse::create(
                content: $content,
                inputTokens: $inputTokens,
                outputTokens: $outputTokens,
                model: $this->model,
                stopReason: 'end_turn',
            );
            $this->budgetTracker?->recordCall($llmResponse);
            $this->budgetTracker?->assertWithinBudget();

            return $llmResponse;
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (Throwable) {
            return $this->complete($request['system'], $request['user']);
        }
    }

    public function completeWithTools(
        string $systemPrompt,
        string $userMessage,
        ToolRegistry $toolRegistry,
        int $maxToolIterations,
    ): LLMResponse {
        \assert('' !== $this->model, 'Model must be a non-empty string');

        $messageBag = new MessageBag(
            Message::forSystem($systemPrompt),
            Message::ofUser($userMessage),
        );

        $options = $this->baseOptions();
        $options['tools'] = $this->buildPlatformTools($toolRegistry->definitions());

        $estimatedInputTokens = $this->estimateInputTokens($systemPrompt, $userMessage);

        $iteration = 0;
        $totalInputTokens = 0;
        $totalOutputTokens = 0;
        while ($iteration < $maxToolIterations) {
            try {
                $deferredResult = $this->invokeWithRetry($messageBag, $options, $estimatedInputTokens);
            } catch (EmptyLLMResponseException $emptyllmResponseException) {
                return $this->emptyToolLoopResponseAndLog($emptyllmResponseException, $iteration, $totalInputTokens, $totalOutputTokens);
            }

            $platformResult = $deferredResult->getResult();
            [$callInput, $callOutput] = $this->extractTokens($deferredResult);
            $totalInputTokens += $callInput;
            $totalOutputTokens += $callOutput;
            $this->rateLimiter()->record($callInput, $callOutput);
            if ($this->budgetTracker instanceof BudgetTracker) {
                $this->budgetTracker->recordCall(LLMResponse::create(
                    content: '',
                    inputTokens: $callInput,
                    outputTokens: $callOutput,
                    model: $this->model,
                    stopReason: 'tool_iteration',
                ));
                $this->budgetTracker->assertWithinBudget();
            }

            $toolCalls = $this->extractToolCalls($platformResult);

            if ([] === $toolCalls) {
                $content = $this->extractText($platformResult);
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
        );
    }

    public function model(): string
    {
        return $this->model;
    }

    private function emptyResponseAndLog(EmptyLLMResponseException $emptyllmResponseException): LLMResponse
    {
        $this->logger->warning('LLM returned a response with no content blocks', [
            'error' => $emptyllmResponseException->getMessage(),
        ]);

        return LLMResponse::create(
            content: '',
            inputTokens: 0,
            outputTokens: 0,
            model: $this->model,
            stopReason: 'empty_content',
        );
    }

    private function emptyToolLoopResponseAndLog(
        EmptyLLMResponseException $emptyllmResponseException,
        int $iteration,
        int $totalInputTokens,
        int $totalOutputTokens,
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
        );
    }

    /**
     * @return list<ToolCall>
     */
    private function extractToolCalls(ResultInterface $result): array
    {
        if ($result instanceof ToolCallResult) {
            return array_values($result->getContent());
        }

        if ($result instanceof MultiPartResult) {
            foreach ($result->getContent() as $part) {
                if ($part instanceof ToolCallResult) {
                    return array_values($part->getContent());
                }
            }
        }

        return [];
    }

    private function extractText(ResultInterface $result): string
    {
        if ($result instanceof TextResult) {
            return $result->getContent();
        }

        if ($result instanceof MultiPartResult) {
            return $result->asText();
        }

        return '';
    }

    /** @param array<string, mixed> $options */
    private function invokeWithRetry(MessageBag $messageBag, array $options, int $estimatedInputTokens): DeferredResult
    {
        $platform = $this->platform();
        $rateLimiter = $this->rateLimiter();
        $retryPolicy = $this->retryPolicy ?? new RetryPolicy();
        $classifier = $this->transientFailureClassifier ?? new TransientFailureClassifier();
        $sleeper = $this->sleeper ?? new UsleepSleeper();
        $retryAfterParser = $this->retryAfterHeaderParser ?? new RetryAfterHeaderParser();

        \assert('' !== $this->model, 'Model must be a non-empty string');

        $maxAttempts = $retryPolicy->maxAttempts();
        $attempt = 1;
        while (true) {
            $rateLimiter->acquire($estimatedInputTokens);

            try {
                $deferredResult = $platform->invoke($this->model, $messageBag, $options);
                $deferredResult->getResult();

                return $deferredResult;
            } catch (Throwable $throwable) {
                if ($classifier->isEmptyContent($throwable)) {
                    throw EmptyLLMResponseException::from($throwable);
                }

                if (!$classifier->isTransient($throwable)) {
                    throw NonTransientLLMFailureException::from($throwable);
                }

                if ($attempt >= $maxAttempts) {
                    throw TransientLLMFailureException::afterExhaustedAttempts($maxAttempts, $throwable);
                }

                $serverHintSeconds = null;
                if ($classifier->isRateLimit($throwable)) {
                    $serverHintSeconds = $retryAfterParser->parse($throwable);
                    if (null !== $serverHintSeconds) {
                        $rateLimiter->pauseUntil(
                            (new DateTimeImmutable())->modify(\sprintf('+%d seconds', $serverHintSeconds)),
                        );
                    }
                }

                $delay = $classifier->isRateLimit($throwable)
                    ? $retryPolicy->rateLimitDelayMs($attempt, $serverHintSeconds)
                    : $retryPolicy->delayMs($attempt);
                $this->logger->warning('LLM call failed, retrying after backoff', [
                    'attempt' => $attempt,
                    'max_attempts' => $maxAttempts,
                    'delay_ms' => $delay,
                    'error' => $throwable->getMessage(),
                ]);
                $sleeper->sleep($delay);
                ++$attempt;
            }
        }
    }

    private function platform(): PlatformInterface
    {
        return $this->platform ?? throw MissingAiPlatformException::create();
    }

    private function rateLimiter(): RateLimiterInterface
    {
        return $this->rateLimiter ?? new NullRateLimiter();
    }

    private function estimateInputTokens(string ...$prompts): int
    {
        $tokenEstimator = $this->tokenEstimator ?? new CharacterBasedTokenEstimator();
        $total = 0;
        foreach ($prompts as $prompt) {
            $total += $tokenEstimator->estimateTokens($prompt, $this->model);
        }

        return $total;
    }

    /** @return array{0: int, 1: int} */
    private function extractTokens(DeferredResult $deferredResult): array
    {
        $metadata = $deferredResult->getMetadata()->all();
        $tokenUsage = $metadata['token_usage'] ?? null;
        if (!$tokenUsage instanceof TokenUsageInterface) {
            return [0, 0];
        }

        $inputTokens = $tokenUsage->getPromptTokens() ?? 0;
        $outputTokens = $tokenUsage->getCompletionTokens() ?? 0;
        $this->tokenUsageRecorder?->record($inputTokens, $outputTokens);

        return [$inputTokens, $outputTokens];
    }

    /**
     * @return array<string, mixed>
     */
    private function baseOptions(): array
    {
        $options = [];
        if (null !== $this->temperature) {
            $options['temperature'] = $this->temperature;
        }

        if ($this->usesAnthropicOptionDialect()) {
            if ($this->providerJsonMode) {
                $options['response_format'] = ['type' => 'json_object'];
            }

            if (null !== $this->maxOutputTokens) {
                $options['max_tokens'] = $this->maxOutputTokens;
            }
        }

        return $options;
    }

    private function usesAnthropicOptionDialect(): bool
    {
        return str_contains($this->model, 'claude');
    }

    /**
     * @param list<ToolDefinition> $definitions
     *
     * @return list<Tool>
     */
    private function buildPlatformTools(array $definitions): array
    {
        return array_map(
            fn (ToolDefinition $toolDefinition): Tool => new Tool(
                reference: new ExecutionReference(class: ToolCall::class, method: $toolDefinition->name),
                name: $toolDefinition->name,
                description: $toolDefinition->description,
                parameters: $this->normalizeSchema($toolDefinition->parametersSchema),
            ),
            $definitions,
        );
    }

    /**
     * @param array<string, mixed> $schema
     *
     * @return array{type: 'object', properties: array<string, array{type: string, description: string}>, required: list<string>, additionalProperties: false}
     */
    private function normalizeSchema(array $schema): array
    {
        $rawProperties = $schema['properties'] ?? [];
        $properties = [];
        if (\is_array($rawProperties)) {
            foreach ($rawProperties as $name => $spec) {
                if (!\is_string($name)) {
                    continue;
                }

                if (!\is_array($spec)) {
                    continue;
                }

                $type = $spec['type'] ?? 'string';
                $description = $spec['description'] ?? '';
                $properties[$name] = [
                    'type' => \is_string($type) ? $type : 'string',
                    'description' => \is_string($description) ? $description : '',
                ];
            }
        }

        $rawRequired = $schema['required'] ?? [];
        $required = [];
        if (\is_array($rawRequired)) {
            foreach ($rawRequired as $name) {
                if (\is_string($name)) {
                    $required[] = $name;
                }
            }
        }

        return [
            'type' => 'object',
            'properties' => $properties,
            'required' => $required,
            'additionalProperties' => false,
        ];
    }
}
