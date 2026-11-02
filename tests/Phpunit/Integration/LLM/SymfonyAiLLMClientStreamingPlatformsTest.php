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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\CallbackTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\Stream\GeminiStreamedProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\Stream\OpenAiStreamedProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\Stream\StreamedProviderInterface;

final class SymfonyAiLLMClientStreamingPlatformsTest extends TestCase
{
    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMRequestTooLargeException
     * @throws MissingAiPlatformException
     * @throws NegativeTokenCountException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    #[DataProvider('streamedProviders')]
    public function test_a_streamed_answer_comes_back_whole_and_is_booked_at_the_usage_the_provider_reported(StreamedProviderInterface $streamedProvider): void
    {
        $response = $streamedProvider->textAnswer('Hello', 120, 7);
        $tokenUsageRecorder = new TokenUsageRecorder();

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($streamedProvider->platform($response), $streamedProvider->model(), new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $streamedProvider->servingPlatform(), streaming: true),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        ))->complete('system', 'user');

        self::assertSame(
            ['Hello', 120, 7, true],
            [$llmResponse->content(), $tokenUsageRecorder->snapshot()->inputTokens(), $tokenUsageRecorder->snapshot()->outputTokens(), $streamedProvider->askedForAStream($response)],
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMRequestTooLargeException
     * @throws MissingAiPlatformException
     * @throws NegativeTokenCountException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    #[DataProvider('streamedProviders')]
    public function test_a_tool_call_the_model_streams_runs_and_the_conversation_goes_on(StreamedProviderInterface $streamedProvider): void
    {
        $lookedUp = [];
        $toolRegistry = new ToolRegistry([new CallbackTool('lookup', 'lookup', static function (array $arguments) use (&$lookedUp): string {
            $lookedUp[] = $arguments;

            return 'contents';
        }, ['type' => 'object', 'properties' => ['path' => ['type' => 'string']], 'required' => ['path']])], new NullLogger());

        $llmResponse = (new SymfonyAiLLMClient(
            new PlatformBinding($streamedProvider->platform($streamedProvider->toolCallAnswer('lookup', ['path' => 'src/A.php']), $streamedProvider->textAnswer('done', 150, 2)), $streamedProvider->model(), new NullLogger()),
            new PlatformRequestConfig(servingPlatform: $streamedProvider->servingPlatform(), streaming: true),
        ))->completeWithTools('system', 'user', $toolRegistry, 3);

        self::assertSame([[['path' => 'src/A.php']], 'done'], [$lookedUp, $llmResponse->content()]);
    }

    /**
     * @return iterable<string, array{StreamedProviderInterface}>
     */
    public static function streamedProviders(): iterable
    {
        yield 'OpenAI (Responses API)' => [new OpenAiStreamedProvider()];
        yield 'Gemini' => [new GeminiStreamedProvider()];
    }
}
