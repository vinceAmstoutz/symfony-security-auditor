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
use Symfony\AI\Platform\Result\ToolCall;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;

/**
 * Runs every tool-using conversation in a concurrency window as a wavefront:
 * each round dispatches the next platform invocation for every still-pending
 * conversation WITHOUT blocking, then resolves them, executes the requested
 * tools against that conversation's own registry, and queues the follow-up
 * round. On an async transport (the symfony/ai DeferredResult contract) the
 * per-round invocations overlap on the wire. A conversation that fails before
 * any of its tools ran falls back to the proven sequential completeWithTools()
 * path (full retry); one that fails after a tool already produced side effects
 * finalizes as an empty `empty_content` response so tools are never executed
 * twice.
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
    ) {}

    /**
     * @param list<array{system: string, user: string, tools: ToolRegistry}> $window
     *
     * @return list<LLMResponse>
     *
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
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
     * @return array<int, array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null}>
     */
    private function initializeConversationStates(array $window): array
    {
        $states = [];
        foreach ($window as $index => $request) {
            $options = $this->platformOptionsFactory->baseOptions();
            $options['tools'] = PlatformToolsMapper::map($request['tools']->definitions());
            $states[$index] = [
                'bag' => new MessageBag(Message::forSystem($request['system']), Message::ofUser($request['user'])),
                'options' => $options,
                'input' => 0,
                'output' => 0,
                'cacheRead' => 0,
                'cacheCreation' => 0,
                'toolsRan' => false,
                'response' => null,
            ];
        }

        return $states;
    }

    /**
     * @param array<int, array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null}> $states
     * @param list<array{system: string, user: string, tools: ToolRegistry}>                                                                                                             $window
     *
     * @return array<int, array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null}>
     *
     * @throws BudgetExceededException
     */
    private function runWavefrontRound(PlatformInterface $platform, array $states, array $window, int $maxToolIterations): array
    {
        $deferred = $this->dispatchPendingInvocations($platform, $states, $window);

        foreach ($deferred as $index => $deferredResult) {
            $states[$index] = $this->advanceConversation($states[$index], $deferredResult, $window[$index], $maxToolIterations);
        }

        return $states;
    }

    /**
     * @param array<int, array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null}> $states
     * @param list<array{system: string, user: string, tools: ToolRegistry}>                                                                                                             $window
     *
     * @return array<int, DeferredResult|null>
     */
    private function dispatchPendingInvocations(PlatformInterface $platform, array $states, array $window): array
    {
        $deferred = [];
        foreach ($states as $index => $state) {
            if ($state['response'] instanceof LLMResponse) {
                continue;
            }

            $this->rateLimiter->acquire($this->promptTokenEstimator->estimate($window[$index]['system'], $window[$index]['user']));

            $deferred[$index] = $this->invokeWithoutThrowing($platform, $state['bag'], $state['options']);
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
     * @param array<int, array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null}> $states
     *
     * @return list<LLMResponse>
     */
    private function collectResponses(array $states, int $maxToolIterations): array
    {
        $responses = [];
        foreach ($states as $state) {
            $responses[] = $state['response'] instanceof LLMResponse
                ? $state['response']
                : $this->toolIterationCapResponse($state, $maxToolIterations);
        }

        return $responses;
    }

    /**
     * @param array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null} $state
     * @param array{system: string, user: string, tools: ToolRegistry}                                                                                                       $request
     *
     * @return array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null}
     *
     * @throws BudgetExceededException
     */
    private function advanceConversation(array $state, ?DeferredResult $deferredResult, array $request, int $maxToolIterations): array
    {
        if (!$deferredResult instanceof DeferredResult) {
            $this->rateLimiter->record(0, 0);

            return $this->abortConversation($state, $request, $maxToolIterations);
        }

        $reconciled = false;

        try {
            $platformResult = $deferredResult->getResult();
            [$callInput, $callOutput, $callCacheRead, $callCacheCreation] = $this->platformResultExtractor->extractTokens($deferredResult);
            $state['input'] += $callInput;
            $state['output'] += $callOutput;
            $state['cacheRead'] += $callCacheRead;
            $state['cacheCreation'] += $callCacheCreation;
            $this->rateLimiter->record($callInput, $callOutput);
            $reconciled = true;
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
                return $this->runToolCalls($state, $toolCalls, $request);
            }

            $state['response'] = LLMResponse::of(
                $this->platformResultExtractor->extractText($platformResult),
                $this->model,
                'end_turn',
                TokenUsageSnapshot::of($state['input'], $state['output'], $state['cacheRead'], $state['cacheCreation']),
            );

            return $state;
        } catch (BudgetExceededException $budgetExceededException) {
            throw $budgetExceededException;
        } catch (Throwable) {
            if (!$reconciled) {
                $this->rateLimiter->record(0, 0);
            }

            return $this->abortConversation($state, $request, $maxToolIterations);
        }
    }

    /**
     * @param array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null} $state
     * @param list<ToolCall>                                                                                                                                                 $toolCalls
     * @param array{system: string, user: string, tools: ToolRegistry}                                                                                                       $request
     *
     * @return array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null}
     */
    private function runToolCalls(array $state, array $toolCalls, array $request): array
    {
        $state['bag']->add(new AssistantMessage(...$toolCalls));
        foreach ($toolCalls as $toolCall) {
            $result = $request['tools']->execute($toolCall->getName(), $toolCall->getArguments());
            $state['bag']->add(new ToolCallMessage($toolCall, $result));
        }

        $state['toolsRan'] = true;

        return $state;
    }

    /**
     * @param array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null} $state
     * @param array{system: string, user: string, tools: ToolRegistry}                                                                                                       $request
     *
     * @return array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null}
     */
    private function abortConversation(array $state, array $request, int $maxToolIterations): array
    {
        if (!$state['toolsRan']) {
            $state['response'] = $this->llmClient->completeWithTools($request['system'], $request['user'], $request['tools'], $maxToolIterations);

            return $state;
        }

        $this->logger->warning('Concurrent tool-using conversation failed after tool execution; keeping recorded tool results', [
            'input_tokens' => $state['input'],
            'output_tokens' => $state['output'],
        ]);
        $state['response'] = LLMResponse::of(
            '',
            $this->model,
            'empty_content',
            TokenUsageSnapshot::of($state['input'], $state['output'], $state['cacheRead'], $state['cacheCreation']),
        );

        return $state;
    }

    /**
     * @param array{bag: MessageBag, options: array<string, mixed>, input: int, output: int, cacheRead: int, cacheCreation: int, toolsRan: bool, response: LLMResponse|null} $state
     */
    private function toolIterationCapResponse(array $state, int $maxToolIterations): LLMResponse
    {
        $this->logger->warning('Tool-using loop hit iteration cap', [
            'max_iterations' => $maxToolIterations,
            'input_tokens' => $state['input'],
            'output_tokens' => $state['output'],
        ]);

        return LLMResponse::of(
            '',
            $this->model,
            'max_tool_iterations',
            TokenUsageSnapshot::of($state['input'], $state['output'], $state['cacheRead'], $state['cacheCreation']),
        );
    }
}
