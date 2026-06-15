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
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\PlatformInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\SleeperInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Delay\UsleepSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\EmptyLLMResponseException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\NullRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TokenEstimator\ResolvingTokenEstimator;

/**
 * Implements the Domain LLM ports on top of the symfony/ai platform. The
 * single-call paths live here; retry, batching, the tool wavefront, the
 * sequential tool loop, and platform result/option/tool mapping live in
 * dedicated collaborators built at construction time.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyAiLLMClient implements ToolBatchCapableLLMClientInterface
{
    public const ?float DEFAULT_TEMPERATURE = null;

    public const bool DEFAULT_PROVIDER_JSON_MODE = false;

    public const ?int DEFAULT_MAX_OUTPUT_TOKENS = null;

    private RateLimiterInterface $rateLimiter;

    private PromptTokenEstimator $promptTokenEstimator;

    private PlatformResultExtractor $platformResultExtractor;

    private PlatformOptionsFactory $platformOptionsFactory;

    private RetryingPlatformInvoker $retryingPlatformInvoker;

    private SequentialToolLoop $sequentialToolLoop;

    private BatchWindowResolver $batchWindowResolver;

    private ToolConversationWavefront $toolConversationWavefront;

    public function __construct(
        ?PlatformInterface $platform,
        private string $model,
        private LoggerInterface $logger,
        private ?float $temperature = self::DEFAULT_TEMPERATURE,
        ?TokenUsageRecorder $tokenUsageRecorder = null,
        RetryPolicy $retryPolicy = new RetryPolicy(),
        TransientFailureClassifier $transientFailureClassifier = new TransientFailureClassifier(),
        SleeperInterface $sleeper = new UsleepSleeper(),
        private ?BudgetTracker $budgetTracker = null,
        bool $providerJsonMode = self::DEFAULT_PROVIDER_JSON_MODE,
        RateLimiterInterface $rateLimiter = new NullRateLimiter(),
        TokenEstimatorInterface $tokenEstimator = new ResolvingTokenEstimator(),
        RetryAfterHeaderParser $retryAfterHeaderParser = new RetryAfterHeaderParser(),
        ?int $maxOutputTokens = self::DEFAULT_MAX_OUTPUT_TOKENS,
    ) {
        $this->rateLimiter = $rateLimiter;
        $this->promptTokenEstimator = new PromptTokenEstimator($tokenEstimator, $model);
        $this->platformResultExtractor = new PlatformResultExtractor($tokenUsageRecorder);
        $platformOptionsFactory = new PlatformOptionsFactory($model, $temperature, $providerJsonMode, $maxOutputTokens);
        $this->platformOptionsFactory = $platformOptionsFactory;

        $this->retryingPlatformInvoker = new RetryingPlatformInvoker(
            $platform,
            $model,
            $logger,
            $this->rateLimiter,
            $retryPolicy,
            $transientFailureClassifier,
            $sleeper,
            $retryAfterHeaderParser,
        );

        $this->sequentialToolLoop = new SequentialToolLoop(
            $model,
            $logger,
            $this->rateLimiter,
            $budgetTracker,
            $this->retryingPlatformInvoker,
            $this->platformResultExtractor,
            $platformOptionsFactory,
            $this->promptTokenEstimator,
        );

        $this->batchWindowResolver = new BatchWindowResolver(
            $platform,
            $model,
            $this->rateLimiter,
            $budgetTracker,
            $this->platformResultExtractor,
            $platformOptionsFactory,
            $this->promptTokenEstimator,
            $this,
        );

        $this->toolConversationWavefront = new ToolConversationWavefront(
            $platform,
            $model,
            $logger,
            $this->rateLimiter,
            $budgetTracker,
            $this->platformResultExtractor,
            $platformOptionsFactory,
            $this->promptTokenEstimator,
            $this,
        );
    }

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

        $estimatedInputTokens = $this->promptTokenEstimator->estimate($systemPrompt, $userMessage);
        try {
            $deferredResult = $this->retryingPlatformInvoker->invoke($messageBag, $this->platformOptionsFactory->baseOptions(), $estimatedInputTokens);
        } catch (EmptyLLMResponseException $emptyllmResponseException) {
            return $this->emptyResponseAndLog($emptyllmResponseException);
        }

        $content = $deferredResult->asText();
        [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens] = $this->platformResultExtractor->extractTokens($deferredResult);

        $this->rateLimiter->record($inputTokens, $outputTokens);

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
            cacheReadTokens: $cacheReadTokens,
            cacheCreationTokens: $cacheCreationTokens,
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
            foreach ($this->batchWindowResolver->resolveWindow($window) as $llmResponse) {
                $responses[] = $llmResponse;
            }
        }

        return $responses;
    }

    public function completeBatchWithTools(array $requests, int $maxConcurrent, int $maxToolIterations): array
    {
        \assert('' !== $this->model, 'Model must be a non-empty string');

        $windowSize = max(1, $maxConcurrent);
        $responses = [];

        foreach (array_chunk($requests, $windowSize) as $window) {
            foreach ($this->toolConversationWavefront->resolveToolWindow($window, $maxToolIterations) as $llmResponse) {
                $responses[] = $llmResponse;
            }
        }

        return $responses;
    }

    public function completeWithTools(
        string $systemPrompt,
        string $userMessage,
        ToolRegistry $toolRegistry,
        int $maxToolIterations,
    ): LLMResponse {
        return $this->sequentialToolLoop->run($systemPrompt, $userMessage, $toolRegistry, $maxToolIterations);
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
}
