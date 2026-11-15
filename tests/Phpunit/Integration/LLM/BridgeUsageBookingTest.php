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
use Symfony\AI\Platform\Bridge\Anthropic\ResultConverter as AnthropicResultConverter;
use Symfony\AI\Platform\Bridge\Gemini\Gemini\ResultConverter as GeminiResultConverter;
use Symfony\AI\Platform\Bridge\OpenResponses\ResultConverter as OpenResponsesResultConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\ResultConverterInterface;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResultExtractor;

final class BridgeUsageBookingTest extends TestCase
{
    private const int ESTIMATED_INPUT_TOKENS = 4321;

    /**
     * @param array<string, mixed>      $answer
     * @param array{int, int, int, int} $expectedTokens input, output, cache read, cache creation
     *
     * @throws NegativeTokenCountException
     */
    #[DataProvider('bridgeAnswers')]
    public function test_it_books_the_usage_a_bridge_reads_from_its_providers_answer(ResultConverterInterface $resultConverter, array $answer, array $expectedTokens): void
    {
        self::assertSame($expectedTokens, (new PlatformResultExtractor(null))->extractTokens($this->answered($resultConverter, $answer), self::ESTIMATED_INPUT_TOKENS));
    }

    /**
     * @param array<string, mixed> $answer
     *
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     */
    #[DataProvider('meteredBridgeAnswers')]
    public function test_it_counts_the_input_a_bridges_provider_meters_against_its_rate_limit(ResultConverterInterface $resultConverter, array $answer, int $meteredInputTokens): void
    {
        $platformResultExtractor = new PlatformResultExtractor(null);
        $deferredResult = $this->answered($resultConverter, $answer);

        self::assertSame($meteredInputTokens, $platformResultExtractor->rateLimitedInputTokens($deferredResult, TokenUsageSnapshot::of(...$platformResultExtractor->extractTokens($deferredResult, self::ESTIMATED_INPUT_TOKENS))));
    }

    /** @return iterable<string, array{ResultConverterInterface, array<string, mixed>, int}> */
    public static function meteredBridgeAnswers(): iterable
    {
        yield 'OpenAI Responses, cache reads and writes counted inside the input' => [new OpenResponsesResultConverter(), self::responsesAnswer(['cached_tokens' => 9000, 'cache_write_tokens' => 3000]), 15000];
        yield 'Anthropic, cache reads and writes counted apart from the input' => [new AnthropicResultConverter(), self::anthropicAnswer(), 3000];
        yield 'Gemini, cached tokens counted inside the prompt' => [new GeminiResultConverter(), self::geminiAnswer(), 15000];
    }

    /** @return iterable<string, array{ResultConverterInterface, array<string, mixed>, array{int, int, int, int}}> */
    public static function bridgeAnswers(): iterable
    {
        yield 'OpenAI Responses, cache reads and writes counted inside the input' => [new OpenResponsesResultConverter(), self::responsesAnswer(['cached_tokens' => 9000, 'cache_write_tokens' => 3000]), [3000, 300, 9000, 3000]];
        yield 'OpenAI Responses, cache reads beside no cache write' => [new OpenResponsesResultConverter(), self::responsesAnswer(['cached_tokens' => 9000, 'cache_write_tokens' => 0]), [6000, 300, 9000, 0]];
        yield 'OpenAI Responses, cache writes before any cache read' => [new OpenResponsesResultConverter(), self::responsesAnswer(['cached_tokens' => 0, 'cache_write_tokens' => 12000]), [3000, 300, 0, 12000]];
        yield 'OpenAI Responses, no cache reported' => [new OpenResponsesResultConverter(), self::responsesAnswer([]), [15000, 300, 0, 0]];
        yield 'Anthropic, cache reads and writes counted apart from the input' => [new AnthropicResultConverter(), self::anthropicAnswer(), [20, 300, 12000, 2980]];
        yield 'Gemini, cached tokens counted inside the prompt beside thoughts counted apart' => [new GeminiResultConverter(), self::geminiAnswer(), [6000, 2300, 9000, 0]];
    }

    /**
     * @param array<string, int> $inputTokensDetails
     *
     * @return array<string, mixed>
     */
    private static function responsesAnswer(array $inputTokensDetails): array
    {
        return [
            'id' => 'resp_1',
            'object' => 'response',
            'model' => 'gpt-6.1-sol',
            'status' => 'completed',
            'output' => [['type' => 'message', 'id' => 'msg_1', 'status' => 'completed', 'role' => 'assistant', 'content' => [['type' => 'output_text', 'text' => '[]', 'annotations' => []]]]],
            'usage' => ['input_tokens' => 15000, 'input_tokens_details' => $inputTokensDetails, 'output_tokens' => 300, 'output_tokens_details' => ['reasoning_tokens' => 100], 'total_tokens' => 15300],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function anthropicAnswer(): array
    {
        return [
            'id' => 'msg_1',
            'type' => 'message',
            'role' => 'assistant',
            'model' => 'claude-opus-5-5',
            'content' => [['type' => 'text', 'text' => '[]']],
            'stop_reason' => 'end_turn',
            'usage' => ['input_tokens' => 20, 'output_tokens' => 300, 'cache_creation_input_tokens' => 2980, 'cache_read_input_tokens' => 12000],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function geminiAnswer(): array
    {
        return [
            'modelVersion' => 'gemini-3.6-flash',
            'candidates' => [['content' => ['role' => 'model', 'parts' => [['text' => '[]']]], 'finishReason' => 'STOP']],
            'usageMetadata' => ['promptTokenCount' => 15000, 'candidatesTokenCount' => 300, 'thoughtsTokenCount' => 2000, 'cachedContentTokenCount' => 9000, 'totalTokenCount' => 17300],
        ];
    }

    /**
     * @param array<string, mixed> $answer
     */
    private function answered(ResultConverterInterface $resultConverter, array $answer): DeferredResult
    {
        $response = (new MockHttpClient(new MockResponse(json_encode($answer, \JSON_THROW_ON_ERROR))))->request('POST', 'https://provider.example/v1');
        $deferredResult = new DeferredResult($resultConverter, new RawHttpResult($response));
        $deferredResult->getResult();

        return $deferredResult;
    }
}
