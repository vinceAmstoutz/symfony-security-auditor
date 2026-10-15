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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\RateLimit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\AI\Platform\Exception\RateLimitExceededException;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\SuggestedWaitParser;

final class SuggestedWaitParserTest extends TestCase
{
    #[DataProvider('messagesNamingAWaitCases')]
    public function test_it_reads_the_wait_a_message_asks_for(string $message, int $expectedMs): void
    {
        self::assertSame($expectedMs, (new SuggestedWaitParser())->milliseconds(new RateLimitExceededException(null, $message), null));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function messagesNamingAWaitCases(): iterable
    {
        yield 'OpenAI seconds' => ['Rate limit reached for gpt-4o on tokens per min (TPM). Please try again in 8.064s. Visit https://platform.openai.com/account/rate-limits.', 8_064];
        yield 'OpenAI milliseconds' => ['Please try again in 120ms.', 120];
        yield 'OpenAI minutes and seconds' => ['Please try again in 1m19.2s.', 79_200];
        yield 'OpenAI whole minutes' => ['Please try again in 6m0s.', 360_000];
        yield 'OpenAI hours' => ['Please try again in 2h.', 7_200_000];
        yield 'Gemini' => ['Quota exceeded for metric: generate_content_free_tier_input_token_count. Please retry in 41.8s.', 41_800];
        yield 'a sentence of its own' => ['Rate limit exceeded. Try again in 3s.', 3_000];
        yield 'a fraction of a millisecond, rounded up' => ['Please try again in 0.0004s.', 1];
        yield 'no wait named' => ['Rate limit exceeded.', 0];
        yield 'a wait without a duration' => ['Please retry in a moment.', 0];
    }

    public function test_it_reads_the_longest_wait_the_messages_of_a_failure_ask_for(): void
    {
        $shorterOutside = new RuntimeException('Please try again in 2s.', previous: new RuntimeException('Please try again in 5s.'));
        $longerOutside = new RuntimeException('Please try again in 5s.', previous: new RuntimeException('Please try again in 2s.'));

        self::assertSame([5_000, 5_000], [(new SuggestedWaitParser())->milliseconds($shorterOutside, null), (new SuggestedWaitParser())->milliseconds($longerOutside, null)]);
    }

    /**
     * @param array<string, list<string>> $headers
     */
    #[DataProvider('tokenWindowResetCases')]
    public function test_it_reads_when_the_token_window_resets(array $headers, int $expectedMs): void
    {
        self::assertSame($expectedMs, (new SuggestedWaitParser())->milliseconds(new RateLimitExceededException(1), $this->answeredWith($headers)));
    }

    /**
     * @return iterable<string, array{array<string, list<string>>, int}>
     */
    public static function tokenWindowResetCases(): iterable
    {
        yield 'minutes and seconds' => [['x-ratelimit-reset-tokens' => ['6m0s']], 360_000];
        yield 'milliseconds' => [['x-ratelimit-reset-tokens' => ['120ms']], 120];
        yield 'the request window alone' => [['x-ratelimit-reset-requests' => ['1s']], 0];
        yield 'no duration' => [['x-ratelimit-reset-tokens' => ['soon']], 0];
        yield 'a duration with text before it' => [['x-ratelimit-reset-tokens' => ['about 6s']], 0];
        yield 'a duration with text after it' => [['x-ratelimit-reset-tokens' => ['6s or so']], 0];
    }

    public function test_it_reads_the_longer_of_the_token_window_reset_and_the_message(): void
    {
        $deferredResult = $this->answeredWith(['x-ratelimit-reset-tokens' => ['1m30s']]);

        self::assertSame([90_000, 120_000], [
            (new SuggestedWaitParser())->milliseconds(new RateLimitExceededException(1, 'Please try again in 8.064s.'), $deferredResult),
            (new SuggestedWaitParser())->milliseconds(new RateLimitExceededException(1, 'Please try again in 2m.'), $deferredResult),
        ]);
    }

    public function test_it_reads_no_reset_from_an_answer_that_is_not_an_http_response(): void
    {
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('')), new InMemoryRawResult(['x-ratelimit-reset-tokens' => '6m0s']));

        self::assertSame(0, (new SuggestedWaitParser())->milliseconds(new RateLimitExceededException(1), $deferredResult));
    }

    public function test_it_reads_no_reset_from_a_response_whose_headers_never_arrived(): void
    {
        $response = self::createStub(ResponseInterface::class);
        $response->method('getHeaders')->willThrowException(new TransportException('Connection reset by peer'));

        self::assertSame(0, (new SuggestedWaitParser())->milliseconds(new RateLimitExceededException(1), new DeferredResult(new PlainConverter(new TextResult('')), new RawHttpResult($response))));
    }

    /**
     * @throws TransportExceptionInterface
     */
    public function test_it_reads_the_token_window_reset_of_the_rate_limited_response_itself(): void
    {
        $response = (new MockHttpClient(new MockResponse('{"error":{"message":"Rate limit reached"}}', [
            'http_code' => 429,
            'response_headers' => ['x-ratelimit-reset-tokens' => '6m0s'],
        ])))->request('POST', 'https://llm.example/v1/chat/completions');

        self::assertSame(360_000, (new SuggestedWaitParser())->milliseconds(new RateLimitExceededException(1), new DeferredResult(new PlainConverter(new TextResult('')), new RawHttpResult($response))));
    }

    /**
     * @param array<string, list<string>> $headers
     */
    private function answeredWith(array $headers): DeferredResult
    {
        $response = self::createStub(ResponseInterface::class);
        $response->method('getHeaders')->willReturn($headers);

        return new DeferredResult(new PlainConverter(new TextResult('')), new RawHttpResult($response));
    }
}
