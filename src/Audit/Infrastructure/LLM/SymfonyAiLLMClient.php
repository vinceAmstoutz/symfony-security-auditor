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

use Override;
use Psr\Log\LoggerInterface;
use Symfony\AI\Platform\Exception\UnexpectedResultTypeException;
use Symfony\AI\Platform\Message\Message;
use Symfony\AI\Platform\Message\MessageBag;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\EmptyLLMResponseException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;

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

    private EmptyLLMResponseFactory $emptyLLMResponseFactory;

    private SequentialToolLoop $sequentialToolLoop;

    private BatchWindowResolver $batchWindowResolver;

    private ToolConversationWavefront $toolConversationWavefront;

    private string $model;

    private LoggerInterface $logger;

    private ?float $temperature;

    private ?BudgetTracker $budgetTracker;

    public function __construct(
        PlatformBinding $platformBinding,
        PlatformRequestConfig $platformRequestConfig = new PlatformRequestConfig(),
        PlatformResilienceConfig $platformResilienceConfig = new PlatformResilienceConfig(),
        PlatformAccountingConfig $platformAccountingConfig = new PlatformAccountingConfig(),
    ) {
        $this->model = $platformBinding->model;
        $this->logger = $platformBinding->logger;
        $this->temperature = $platformRequestConfig->temperature;
        $this->budgetTracker = $platformAccountingConfig->budgetTracker;
        $this->rateLimiter = $platformResilienceConfig->rateLimiter;
        $this->promptTokenEstimator = new PromptTokenEstimator($platformRequestConfig->tokenEstimator, $platformBinding->model);
        $this->platformResultExtractor = new PlatformResultExtractor($platformAccountingConfig->tokenUsageRecorder);
        $platformOptionsFactory = new PlatformOptionsFactory($platformBinding->model, $platformRequestConfig->temperature, $platformRequestConfig->providerJsonMode, $platformBinding->maxOutputTokens);
        $this->platformOptionsFactory = $platformOptionsFactory;

        $this->retryingPlatformInvoker = new RetryingPlatformInvoker(
            $platformBinding->platform,
            $platformBinding->model,
            $platformBinding->logger,
            $this->rateLimiter,
            $platformResilienceConfig->retryPolicy,
            $platformResilienceConfig->transientFailureClassifier,
            $platformResilienceConfig->sleeper,
            $platformResilienceConfig->retryAfterHeaderParser,
        );
        $this->emptyLLMResponseFactory = new EmptyLLMResponseFactory();

        $this->sequentialToolLoop = new SequentialToolLoop(
            $platformBinding->model,
            $platformBinding->logger,
            $this->rateLimiter,
            $platformAccountingConfig->budgetTracker,
            $this->retryingPlatformInvoker,
            $this->platformResultExtractor,
            $platformOptionsFactory,
            $this->promptTokenEstimator,
            $this->emptyLLMResponseFactory,
        );

        $this->batchWindowResolver = new BatchWindowResolver(
            $platformBinding->platform,
            $platformBinding->model,
            $this->rateLimiter,
            $platformAccountingConfig->budgetTracker,
            $this->platformResultExtractor,
            $platformOptionsFactory,
            $this->promptTokenEstimator,
            $this,
        );

        $this->toolConversationWavefront = new ToolConversationWavefront(
            $platformBinding->platform,
            $platformBinding->model,
            $platformBinding->logger,
            $this->rateLimiter,
            $platformAccountingConfig->budgetTracker,
            $this->platformResultExtractor,
            $platformOptionsFactory,
            $this->promptTokenEstimator,
            $this,
            $this->retryingPlatformInvoker,
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws UnexpectedResultTypeException
     */
    #[Override]
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

        try {
            $content = $deferredResult->asText();
            [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens] = $this->platformResultExtractor->extractTokens($deferredResult);
        } catch (Throwable $throwable) {
            $this->rateLimiter->record(0, 0);

            throw $throwable;
        }

        $this->rateLimiter->record($inputTokens, $outputTokens);

        $this->logger->debug('symfony/ai platform responded', [
            'content_length' => \strlen($content),
            'input_tokens' => $inputTokens,
            'output_tokens' => $outputTokens,
        ]);

        $llmResponse = LLMResponse::of(
            $content,
            $this->model,
            'end_turn',
            TokenUsageSnapshot::of($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens),
        );
        $this->budgetTracker?->recordCall($llmResponse);
        $this->budgetTracker?->assertWithinBudget();

        return $llmResponse;
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    #[Override]
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

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     */
    #[Override]
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

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    #[Override]
    public function completeWithTools(
        string $systemPrompt,
        string $userMessage,
        ToolRegistry $toolRegistry,
        int $maxToolIterations,
    ): LLMResponse {
        return $this->sequentialToolLoop->run($systemPrompt, $userMessage, $toolRegistry, $maxToolIterations);
    }

    #[Override]
    public function model(): string
    {
        return $this->model;
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function emptyResponseAndLog(EmptyLLMResponseException $emptyllmResponseException): LLMResponse
    {
        $this->logger->warning('LLM returned a response with no content blocks', [
            'error' => $emptyllmResponseException->getMessage(),
        ]);

        return $this->emptyLLMResponseFactory->create($this->model, TokenUsageSnapshot::of(0, 0));
    }
}
