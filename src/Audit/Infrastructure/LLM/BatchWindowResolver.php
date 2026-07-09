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
use Symfony\AI\Platform\Result\DeferredResult;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;

/**
 * Dispatches every request in a concurrency window via the platform WITHOUT
 * blocking, then resolves them. When the platform's transport is async (the
 * symfony/ai DeferredResult contract), the resolutions overlap on the wire.
 * Any request that fails to dispatch or resolve falls back to the proven
 * sequential complete() path (full retry) so the batch path is never less
 * correct than the per-call path.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BatchWindowResolver
{
    public function __construct(
        private ?PlatformInterface $platform,
        private string $model,
        private RateLimiterInterface $rateLimiter,
        private ?BudgetTracker $budgetTracker,
        private PlatformResultExtractor $platformResultExtractor,
        private PlatformOptionsFactory $platformOptionsFactory,
        private PromptTokenEstimator $promptTokenEstimator,
        private LLMClientInterface $llmClient,
        private LoggerInterface $logger,
    ) {}

    /**
     * @param list<array{system: string, user: string}> $window
     *
     * @return list<LLMResponse>
     *
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function resolveWindow(array $window): array
    {
        \assert('' !== $this->model, 'Model must be a non-empty string');

        $platform = $this->platform ?? throw MissingAiPlatformException::create();
        $deferred = [];
        foreach ($window as $index => $request) {
            $messageBag = new MessageBag(
                Message::forSystem($request['system']),
                Message::ofUser($request['user']),
            );
            $estimatedInputTokens = $this->promptTokenEstimator->estimate($request['system'], $request['user']);
            $this->rateLimiter->acquire($estimatedInputTokens);

            try {
                $deferred[$index] = $platform->invoke($this->model, $messageBag, $this->platformOptionsFactory->baseOptions());
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
     *
     * @throws BudgetExceededException
     */
    private function resolveOne(?DeferredResult $deferredResult, array $request): LLMResponse
    {
        if (!$deferredResult instanceof DeferredResult) {
            $this->rateLimiter->record(0, 0);

            return $this->llmClient->complete($request['system'], $request['user']);
        }

        $reconciled = false;

        try {
            $content = $deferredResult->asText();
            [$inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens] = $this->platformResultExtractor->extractTokens($deferredResult);
            $this->rateLimiter->record($inputTokens, $outputTokens);
            $reconciled = true;

            $llmResponse = LLMResponse::of(
                $content,
                $this->model,
                'end_turn',
                TokenUsageSnapshot::of($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens),
            );
            $this->budgetTracker?->recordCall($llmResponse);
            $this->budgetTracker?->assertWithinBudget();

            return $llmResponse;
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (Throwable) {
            if (!$reconciled) {
                $this->rateLimiter->record(0, 0);
            }

            $this->logger->warning('Batch-window response failed to resolve after dispatch; falling back to a fresh complete() call that may duplicate provider billing for the already-dispatched request');

            return $this->llmClient->complete($request['system'], $request['user']);
        }
    }
}
