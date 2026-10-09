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

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\Exception\BadRequestException;
use Symfony\AI\Platform\Exception\MaxOutputTokensException;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Contracts\HttpClient\ResponseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\StructuredVulnerabilityCollectionSession;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FlakyPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\MessageCollectingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedDeferredPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedTokenUsagePlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

/**
 * Vertex AI takes its API key as the `?key=` query parameter, so a transport
 * failure quotes it inside the URL it names. Whatever form a provider failure
 * takes on its way out, the credential stays out of the exception message the
 * console and an MCP client read, and out of every log record.
 */
final class SymfonyAiLLMClientCredentialRedactionTest extends TestCase
{
    private const string SECRET = 'AIzaSyDUMMYSECRETKEY1234567890abcdef';

    private const string ENDPOINT = 'https://aiplatform.googleapis.com/v1/publishers/google/models/gemini-2.5-pro:generateContent';

    private const string TOO_LONG_AT_THE_ENDPOINT = 'prompt is too long for "https://aiplatform.googleapis.com/v1/publishers/google/models/gemini-2.5-pro:generateContent?key=AIzaSyDUMMYSECRETKEY1234567890abcdef".';

    private const string TOO_LONG_WITHOUT_THE_KEY = 'prompt is too long for "https://aiplatform.googleapis.com/v1/publishers/google/models/gemini-2.5-pro:generateContent?key=***REDACTED***".';

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_a_transient_failure_that_exhausts_every_attempt_keeps_the_query_key_out_of_the_message_and_the_logs(): void
    {
        $messageCollectingLogger = new MessageCollectingLogger();
        $idleTimeout = static fn (): TransportException => new TransportException(\sprintf('Idle timeout reached for "%s?key=%s".', self::ENDPOINT, self::SECRET));
        $client = $this->client(new FlakyPlatform([$idleTimeout(), $idleTimeout(), $idleTimeout()]), $messageCollectingLogger);

        try {
            $client->complete('sys', 'usr');
            self::fail('Three failed attempts must abort the call');
        } catch (TransientLLMFailureException $transientllmFailureException) {
            self::assertSame(\sprintf('LLM call failed after 3 attempts: Idle timeout reached for "%s?key=***REDACTED***".', self::ENDPOINT), $transientllmFailureException->getMessage());
        }

        $retries = array_values(array_filter($messageCollectingLogger->records, static fn (array $record): bool => 'LLM call failed, retrying after backoff' === $record[0]));
        self::assertCount(2, $retries);
        foreach ($retries as [, $context]) {
            self::assertSame(\sprintf('Idle timeout reached for "%s?key=***REDACTED***".', self::ENDPOINT), $context['error']);
        }

        self::assertStringNotContainsString(self::SECRET, json_encode($messageCollectingLogger->records, \JSON_THROW_ON_ERROR));
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_a_non_transient_failure_keeps_the_query_key_out_of_the_message(): void
    {
        $client = $this->client(new FlakyPlatform([new TransportException(\sprintf('HTTP/2 401 returned for "%s?alt=sse&key=%s".', self::ENDPOINT, self::SECRET))]), new MessageCollectingLogger());

        try {
            $client->complete('sys', 'usr');
            self::fail('A 401 must abort the call');
        } catch (NonTransientLLMFailureException $nonTransientLLMFailureException) {
            self::assertSame(\sprintf('LLM call failed with non-transient error: HTTP/2 401 returned for "%s?alt=sse&key=***REDACTED***".', self::ENDPOINT), $nonTransientLLMFailureException->getMessage());
        }
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_a_refusal_as_too_large_keeps_the_query_key_out_of_the_message(): void
    {
        $client = $this->client(new FlakyPlatform([new TransportException(\sprintf('The input exceeds the maximum number of tokens (HTTP 400 for "%s?key=%s").', self::ENDPOINT, self::SECRET))]), new MessageCollectingLogger());

        try {
            $client->complete('sys', 'usr');
            self::fail('A prompt the model cannot take in must be refused');
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            self::assertSame(\sprintf('The model cannot fit the request: The input exceeds the maximum number of tokens (HTTP 400 for "%s?key=***REDACTED***").', self::ENDPOINT), $llmRequestTooLargeException->getMessage());
        }
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_an_answer_with_no_usable_content_logs_the_failure_without_the_query_key(): void
    {
        $messageCollectingLogger = new MessageCollectingLogger();
        $client = $this->client(new FlakyPlatform([new MaxOutputTokensException(\sprintf('Output limit reached for "%s?key=%s".', self::ENDPOINT, self::SECRET))]), $messageCollectingLogger);

        $client->complete('sys', 'usr');

        self::assertContains(
            ['LLM returned a response with no content blocks', ['stop_reason' => 'length', 'error' => \sprintf('LLM returned a response with no content: Output limit reached for "%s?key=***REDACTED***".', self::ENDPOINT)]],
            $messageCollectingLogger->records,
        );
        self::assertStringNotContainsString(self::SECRET, json_encode($messageCollectingLogger->records, \JSON_THROW_ON_ERROR));
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_a_concurrent_conversation_the_model_cannot_fit_hands_back_the_refusal_without_the_query_key(): void
    {
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = $this->clientScripted(new ScriptedTokenUsagePlatform([new BadRequestException(self::TOO_LONG_AT_THE_ENDPOINT)], []), $messageCollectingLogger);

        $responses = $symfonyAiLLMClient->completeBatchWithTools([$this->toolRequest()], 2, 3);

        self::assertTrue($responses[0]->isRequestTooLarge());
        self::assertSame(self::TOO_LONG_WITHOUT_THE_KEY, $responses[0]->content());
        self::assertContains(
            ['Concurrent tool-using conversation refused as too large for the model before any tool ran; its chunk is handed back to be split', ['error' => self::TOO_LONG_WITHOUT_THE_KEY]],
            $messageCollectingLogger->records,
        );
        self::assertStringNotContainsString(self::SECRET, json_encode($messageCollectingLogger->records, \JSON_THROW_ON_ERROR));
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_a_concurrent_conversation_that_outgrew_the_model_after_a_tool_ran_is_logged_without_the_query_key(): void
    {
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = $this->clientScripted(new ScriptedTokenUsagePlatform([
            new ToolCallResult([new ToolCall('call-1', 'record_vulnerability', $this->finding())]),
            new BadRequestException(self::TOO_LONG_AT_THE_ENDPOINT),
        ], [new TokenUsage(promptTokens: 7, completionTokens: 3)]), $messageCollectingLogger);

        $symfonyAiLLMClient->completeBatchWithTools([$this->toolRequest()], 2, 3);

        self::assertContains(
            ['Concurrent tool-using conversation outgrew the model input limit after tool results were appended; it ends as an empty response and keeps the tool results already recorded', ['input_tokens' => 7, 'output_tokens' => 3, 'error' => self::TOO_LONG_WITHOUT_THE_KEY]],
            $messageCollectingLogger->records,
        );
        self::assertStringNotContainsString(self::SECRET, json_encode($messageCollectingLogger->records, \JSON_THROW_ON_ERROR));
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_a_concurrent_conversation_ended_without_usable_content_is_logged_without_the_query_key(): void
    {
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = $this->clientScripted(new ScriptedTokenUsagePlatform([new MaxOutputTokensException(\sprintf('Output limit reached for "%s?key=%s".', self::ENDPOINT, self::SECRET))], []), $messageCollectingLogger);

        $symfonyAiLLMClient->completeBatchWithTools([$this->toolRequest()], 2, 3);

        self::assertContains(
            ['Concurrent tool-using conversation ended without usable content; it is answered as a degraded response and keeps the tool results already recorded', ['stop_reason' => 'length', 'input_tokens' => 0, 'output_tokens' => 0, 'error' => \sprintf('Output limit reached for "%s?key=***REDACTED***".', self::ENDPOINT)]],
            $messageCollectingLogger->records,
        );
        self::assertStringNotContainsString(self::SECRET, json_encode($messageCollectingLogger->records, \JSON_THROW_ON_ERROR));
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     */
    public function test_a_batched_request_the_model_cannot_fit_hands_back_the_refusal_without_the_query_key(): void
    {
        $messageCollectingLogger = new MessageCollectingLogger();
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new ThrowingConverter(new BadRequestException(self::TOO_LONG_AT_THE_ENDPOINT)), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedDeferredPlatform, 'gemini-2.5-pro', $messageCollectingLogger),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        );

        $responses = $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u']], 2);

        self::assertTrue($responses[0]->isRequestTooLarge());
        self::assertSame(self::TOO_LONG_WITHOUT_THE_KEY, $responses[0]->content());
        self::assertContains(
            ['Batch request refused as too large for the model; it is answered as request_too_large so the caller can act on that request alone', ['error' => self::TOO_LONG_WITHOUT_THE_KEY]],
            $messageCollectingLogger->records,
        );
        self::assertStringNotContainsString(self::SECRET, json_encode($messageCollectingLogger->records, \JSON_THROW_ON_ERROR));
    }

    private function client(FlakyPlatform $flakyPlatform, MessageCollectingLogger $messageCollectingLogger): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($flakyPlatform, 'gemini-2.5-pro', $messageCollectingLogger),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        );
    }

    private function clientScripted(ScriptedTokenUsagePlatform $scriptedTokenUsagePlatform, MessageCollectingLogger $messageCollectingLogger): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'gemini-2.5-pro', $messageCollectingLogger),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        );
    }

    /**
     * @return array{system: string, user: string, tools: ToolRegistry}
     *
     * @throws InvalidToolRegistryException
     */
    private function toolRequest(): array
    {
        return ['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry];
    }

    /**
     * @return array<string, mixed>
     */
    private function finding(): array
    {
        return [
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => 'recorded before the conversation outgrew the model',
            'description' => 'desc',
            'file_path' => 'src/A.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.9,
        ];
    }
}
