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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SymfonyAiLLMClient implements LLMClientInterface
{
    public const float DEFAULT_TEMPERATURE = 0.0;

    public const bool DEFAULT_PROMPT_CACHING = false;

    public const bool DEFAULT_PROVIDER_JSON_MODE = false;

    public function __construct(
        private PlatformInterface $platform,
        private string $model,
        private LoggerInterface $logger,
        private float $temperature = self::DEFAULT_TEMPERATURE,
        private bool $promptCaching = self::DEFAULT_PROMPT_CACHING,
        private ?TokenUsageRecorder $tokenUsageRecorder = null,
        private ?RetryPolicy $retryPolicy = null,
        private ?TransientFailureClassifier $transientFailureClassifier = null,
        private ?SleeperInterface $sleeper = null,
        private ?BudgetTracker $budgetTracker = null,
        private bool $providerJsonMode = self::DEFAULT_PROVIDER_JSON_MODE,
    ) {}

    public function complete(string $systemPrompt, string $userMessage): LLMResponse
    {
        $this->logger->debug('Invoking symfony/ai platform', [
            'system_length' => \strlen($systemPrompt),
            'user_length' => \strlen($userMessage),
            'temperature' => $this->temperature,
            'prompt_caching' => $this->promptCaching,
        ]);

        $messageBag = new MessageBag(
            Message::forSystem($systemPrompt),
            Message::ofUser($userMessage),
        );

        \assert('' !== $this->model, 'Model must be a non-empty string');

        $deferredResult = $this->invokeWithRetry($messageBag, $this->baseOptions());
        $content = $deferredResult->asText();
        [$inputTokens, $outputTokens] = $this->extractTokens($deferredResult);

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

        $iteration = 0;
        $totalInputTokens = 0;
        $totalOutputTokens = 0;
        while ($iteration < $maxToolIterations) {
            $deferredResult = $this->invokeWithRetry($messageBag, $options);
            $platformResult = $deferredResult->getResult();
            [$callInput, $callOutput] = $this->extractTokens($deferredResult);
            $totalInputTokens += $callInput;
            $totalOutputTokens += $callOutput;
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
    private function invokeWithRetry(MessageBag $messageBag, array $options): DeferredResult
    {
        $retryPolicy = $this->retryPolicy ?? new RetryPolicy();
        $classifier = $this->transientFailureClassifier ?? new TransientFailureClassifier();
        $sleeper = $this->sleeper ?? new UsleepSleeper();

        \assert('' !== $this->model, 'Model must be a non-empty string');

        $maxAttempts = $retryPolicy->maxAttempts();
        $attempt = 1;
        while (true) {
            try {
                return $this->platform->invoke($this->model, $messageBag, $options);
            } catch (Throwable $throwable) {
                if (!$classifier->isTransient($throwable)) {
                    throw NonTransientLLMFailureException::from($throwable);
                }

                if ($attempt >= $maxAttempts) {
                    throw TransientLLMFailureException::afterExhaustedAttempts($maxAttempts, $throwable);
                }

                $delay = $classifier->isRateLimit($throwable)
                    ? $retryPolicy->rateLimitDelayMs($attempt)
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
        $options = ['temperature' => $this->temperature];
        if ($this->promptCaching) {
            $options['cache_control'] = ['type' => 'ephemeral'];
        }

        if ($this->providerJsonMode) {
            // OpenAI-compatible JSON mode. Honored by OpenAI / Mistral / Ollama;
            // Anthropic does not expose this knob and the option is silently
            // dropped by providers that do not recognize it. The prompt
            // contract ("Return ONLY the JSON array") remains authoritative.
            $options['response_format'] = ['type' => 'json_object'];
        }

        return $options;
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
