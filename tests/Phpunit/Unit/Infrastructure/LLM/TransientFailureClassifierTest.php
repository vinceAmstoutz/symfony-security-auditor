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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\AI\Platform\Exception\ContentFilterException;
use Symfony\AI\Platform\Exception\ExceedContextSizeException;
use Symfony\AI\Platform\Exception\MalformedToolCallException;
use Symfony\AI\Platform\Exception\MaxOutputTokensException;
use Symfony\AI\Platform\Exception\ServerException;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;

final class TransientFailureClassifierTest extends TestCase
{
    #[DataProvider('transientCases')]
    public function test_it_recognizes_transient_failures(Throwable $throwable): void
    {
        self::assertTrue((new TransientFailureClassifier())->isTransient($throwable));
    }

    /** @return iterable<string, array{Throwable}> */
    public static function transientCases(): iterable
    {
        yield 'typed_server_exception_without_transient_hints' => [new ServerException(null, 'provider hiccup')];
        yield 'malformed_tool_call_is_a_sampling_glitch' => [new MalformedToolCallException('Invalid JSON in tool arguments: HTTP 400')];
        yield 'wrapped_malformed_tool_call' => [new RuntimeException('HTTP 400 Bad Request', previous: new MalformedToolCallException('bad arguments'))];
        yield 'http_429' => [new RuntimeException('HTTP 429 Too Many Requests')];
        yield 'http_500' => [new RuntimeException('Server returned HTTP 500')];
        yield 'http_502' => [new RuntimeException('Bad Gateway 502')];
        yield 'http_503' => [new RuntimeException('Service Unavailable (HTTP 503)')];
        yield 'http_504' => [new RuntimeException('Gateway Timeout (504)')];
        yield 'http_529_overloaded' => [new RuntimeException('HTTP 529: Overloaded')];
        yield 'overloaded_phrasing' => [new RuntimeException('The Anthropic API is currently overloaded, please retry')];
        yield 'rate_limit_phrasing' => [new RuntimeException('Rate limit exceeded')];
        yield 'timeout_phrasing' => [new RuntimeException('Request timed out after 30s')];
        yield 'temporarily_unavailable' => [new RuntimeException('Provider temporarily unavailable')];
        yield 'connection_reset' => [new RuntimeException('Connection reset by peer')];
        yield 'connection_refused' => [new RuntimeException('Connection refused: localhost:443')];
        yield 'curl_failed_to_connect' => [new RuntimeException("cURL error 7: Failed to connect to api.anthropic.com port 443 after 21 ms: Couldn't connect to server")];
        yield 'curl_could_not_resolve_host' => [new RuntimeException('cURL error 6: Could not resolve host: api.anthropic.com')];
        yield 'php_stream_name_resolution_failure' => [new RuntimeException('php_network_getaddresses: getaddrinfo for api.anthropic.com failed: Temporary failure in name resolution')];
        yield 'wrapped_transient' => [
            new RuntimeException(
                'API call failed',
                previous: new RuntimeException('underlying: 503 service unavailable'),
            ),
        ];
        yield 'transient_code_with_embedded_non_transient_digits' => [new RuntimeException('HTTP 500 Internal Server Error (request id 400123)')];
        yield 'timeout_message_with_embedded_non_transient_digits' => [new RuntimeException('cURL error 28: timed out after 1400 ms')];
        yield 'rate_limit_quota_with_thousands_separator' => [new RuntimeException("This request would exceed your organization's rate limit of 400,000 input tokens per minute")];
        yield 'timeout_with_thousands_separated_duration' => [new RuntimeException('Request timed out after 1,400 ms')];
        yield 'rate_limit_body_carrying_a_non_transient_status_number' => [new RuntimeException('Rate limit exceeded. Used 29596, Requested 404. Please try again in 1s.')];
    }

    #[DataProvider('nonTransientCases')]
    public function test_it_recognizes_non_transient_failures(Throwable $throwable): void
    {
        self::assertFalse((new TransientFailureClassifier())->isTransient($throwable));
    }

    #[DataProvider('hyphenatedIdentifierCases')]
    public function test_it_does_not_mistake_a_status_like_number_embedded_in_a_hyphenated_identifier_for_a_real_status_code(Throwable $throwable): void
    {
        self::assertFalse((new TransientFailureClassifier())->isTransient($throwable));
    }

    /** @return iterable<string, array{Throwable}> */
    public static function hyphenatedIdentifierCases(): iterable
    {
        yield 'status_code_embedded_in_request_id' => [new RuntimeException('request id abc-500-xyz failed')];
        yield 'status_code_embedded_in_model_name' => [new RuntimeException('the model gpt-4o-500 is not available')];
    }

    #[DataProvider('rateLimitCases')]
    public function test_it_recognizes_rate_limit_failures(Throwable $throwable): void
    {
        self::assertTrue((new TransientFailureClassifier())->isRateLimit($throwable));
    }

    /** @return iterable<string, array{Throwable}> */
    public static function rateLimitCases(): iterable
    {
        yield 'http_429' => [new RuntimeException('HTTP 429 Too Many Requests')];
        yield 'too_many_requests_phrasing' => [new RuntimeException('too many requests')];
        yield 'rate_limit_phrasing' => [new RuntimeException('Rate limit exceeded')];
        yield 'rate_limit_underscore' => [new RuntimeException('rate_limit error')];
        yield 'wrapped_rate_limit' => [
            new RuntimeException(
                'API call failed',
                previous: new RuntimeException('underlying: 429 rate limit hit'),
            ),
        ];
    }

    #[DataProvider('nonRateLimitCases')]
    public function test_it_does_not_classify_non_rate_limit_errors_as_rate_limit(Throwable $throwable): void
    {
        self::assertFalse((new TransientFailureClassifier())->isRateLimit($throwable));
    }

    /** @return iterable<string, array{Throwable}> */
    public static function nonRateLimitCases(): iterable
    {
        yield 'http_503_transient_but_not_rate_limit' => [new RuntimeException('HTTP 503 Service Unavailable')];
        yield 'http_529_transient_but_not_rate_limit' => [new RuntimeException('HTTP 529 Overloaded')];
        yield 'connection_reset' => [new RuntimeException('Connection reset by peer')];
        yield 'http_401_non_transient' => [new RuntimeException('HTTP 401 Unauthorized')];
        yield 'unknown_error' => [new RuntimeException('Something went wrong')];
        yield 'thousands_separated_figure_is_not_a_status_code' => [new RuntimeException('elapsed 1,429 ms')];
        yield 'decimal_figure_is_not_a_status_code' => [new RuntimeException('429.5 units consumed')];
    }

    /** @return iterable<string, array{Throwable}> */
    public static function nonTransientCases(): iterable
    {
        yield 'http_400_bad_request' => [new RuntimeException('HTTP 400 Bad Request')];
        yield 'http_401_unauthorized' => [new RuntimeException('Unauthorized: 401')];
        yield 'http_403_forbidden' => [new RuntimeException('Forbidden: 403')];
        yield 'http_404_not_found' => [new RuntimeException('Not Found (404)')];
        yield 'http_422_validation' => [new RuntimeException('422 Unprocessable Entity')];
        yield 'http_400_at_sentence_end' => [new RuntimeException('The provider rejected the request with HTTP 400.')];
        yield 'non_transient_code_with_embedded_transient_digits' => [new RuntimeException('HTTP 401 Unauthorized (client waited 5001 ms)')];
        yield 'invalid_api_key' => [new RuntimeException('Invalid API key provided')];
        yield 'authentication_failed' => [new RuntimeException('authentication failed')];
        yield 'unknown_error_phrasing' => [new RuntimeException('Something went wrong without identifiable signal')];
        yield 'non_transient_wins_over_transient_in_chain' => [
            new RuntimeException('connection reset', previous: new RuntimeException('HTTP 401')),
        ];
        yield 'content_filter_is_not_retried' => [new ContentFilterException('Blocked by the safety system')];
    }

    #[DataProvider('degradedStopReasonCases')]
    public function test_it_names_the_stop_reason_of_an_answer_the_provider_delivered_as_a_failure(Throwable $throwable, ?string $expectedStopReason): void
    {
        self::assertSame($expectedStopReason, (new TransientFailureClassifier())->degradedStopReason($throwable));
    }

    /** @return iterable<string, array{Throwable, ?string}> */
    public static function degradedStopReasonCases(): iterable
    {
        yield 'output_token_limit' => [new MaxOutputTokensException('The response was cut off'), 'length'];
        yield 'wrapped_output_token_limit' => [new RuntimeException('call failed', previous: new MaxOutputTokensException('cut off')), 'length'];
        yield 'content_filter' => [new ContentFilterException('Blocked by the safety system'), 'content-filter'];
        yield 'wrapped_content_filter' => [new RuntimeException('call failed', previous: new ContentFilterException('blocked')), 'content-filter'];
        yield 'output_limit_wins_over_a_filter_further_down_the_chain' => [new MaxOutputTokensException('cut off', previous: new ContentFilterException('blocked')), 'length'];
        yield 'filter_wins_over_empty_content_wording' => [new ContentFilterException('Response does not contain any content.'), 'content-filter'];
        yield 'empty_content' => [new RuntimeException('Response does not contain any content.'), 'empty_content'];
        yield 'transient_failure' => [new RuntimeException('HTTP 503 Service Unavailable'), null];
        yield 'malformed_tool_call' => [new MalformedToolCallException('bad arguments'), null];
    }

    #[DataProvider('emptyContentCases')]
    public function test_it_recognizes_empty_content_failures(Throwable $throwable): void
    {
        self::assertTrue((new TransientFailureClassifier())->isEmptyContent($throwable));
    }

    /** @return iterable<string, array{Throwable}> */
    public static function emptyContentCases(): iterable
    {
        yield 'symfony_ai_canonical_message' => [new RuntimeException('Response does not contain any content.')];
        yield 'response_does_not_contain_variant' => [new RuntimeException('Response does not contain text blocks')];
        yield 'no_content_blocks_variant' => [new RuntimeException('Anthropic returned no content blocks')];
        yield 'case_insensitive_match' => [new RuntimeException('RESPONSE DOES NOT CONTAIN ANY CONTENT.')];
        yield 'wrapped_empty_content' => [
            new RuntimeException(
                'platform invoke failed',
                previous: new RuntimeException('Response does not contain any content.'),
            ),
        ];
    }

    #[DataProvider('nonEmptyContentCases')]
    public function test_it_does_not_classify_unrelated_errors_as_empty_content(Throwable $throwable): void
    {
        self::assertFalse((new TransientFailureClassifier())->isEmptyContent($throwable));
    }

    /** @return iterable<string, array{Throwable}> */
    public static function nonEmptyContentCases(): iterable
    {
        yield 'transient_503' => [new RuntimeException('HTTP 503 Service Unavailable')];
        yield 'unauthorized_401' => [new RuntimeException('HTTP 401 Unauthorized')];
        yield 'rate_limit' => [new RuntimeException('rate_limit exceeded')];
        yield 'unrelated_runtime_error' => [new RuntimeException('connection reset by peer')];
    }

    #[DataProvider('requestTooLargeCases')]
    public function test_it_recognizes_a_request_the_model_cannot_fit(Throwable $throwable): void
    {
        self::assertTrue((new TransientFailureClassifier())->isRequestTooLarge($throwable));
    }

    /** @return iterable<string, array{Throwable}> */
    public static function requestTooLargeCases(): iterable
    {
        yield 'anthropic_prompt_too_long' => [new RuntimeException('prompt is too long: 213462 tokens > 200000 maximum')];
        yield 'openai_maximum_context_length' => [new RuntimeException("This model's maximum context length is 128000 tokens. However, your messages resulted in 131072 tokens. Please reduce the length of the messages.")];
        yield 'openai_context_length_exceeded_code' => [new RuntimeException('context_length_exceeded')];
        yield 'mistral_too_large_for_model' => [new RuntimeException('Prompt contains 40000 tokens, too large for model with 32768 maximum context length')];
        yield 'gemini_exceeds_maximum_tokens' => [new RuntimeException('The input token count (1100000) exceeds the maximum number of tokens allowed (1048576).')];
        yield 'bedrock_input_too_long' => [new RuntimeException('Input is too long for requested model.')];
        yield 'anthropic_request_too_large_type' => [new RuntimeException('request_too_large: Request exceeds the maximum size')];
        yield 'request_too_large_phrase' => [new RuntimeException('Request too large')];
        yield 'too_many_tokens' => [new RuntimeException('Too many tokens in the request')];
        yield 'http_413' => [new RuntimeException('HTTP 413 Payload Too Large')];
        yield 'wrapped_prompt_too_long' => [
            new RuntimeException(
                'LLM call failed',
                previous: new RuntimeException('prompt is too long: 250000 tokens > 200000 maximum'),
            ),
        ];
        yield 'openai_responses_context_window' => [new RuntimeException('Your input exceeds the context window of this model. Please reduce the length of your input.')];
        yield 'vllm_exceeds_max_model_len' => [new RuntimeException('This maximum context the prompt (9000 tokens) exceeds the max_model_len (8192)')];
        yield 'anthropic_input_and_max_tokens_exceed_context_limit' => [new RuntimeException('input length and `max_tokens` exceed context limit: 196000 + 4096 > 200000, decrease input length or `max_tokens` and try again')];
        yield 'llama_cpp_exceeds_available_context_size' => [new RuntimeException('the request exceeds the available context size, try increasing it')];
        yield 'typed_exceed_context_size_with_no_hint_in_message' => [new ExceedContextSizeException('overflow')];
        yield 'wrapped_typed_exceed_context_size' => [
            new RuntimeException('LLM call failed', previous: new ExceedContextSizeException('overflow')),
        ];
    }

    #[DataProvider('notRequestTooLargeCases')]
    public function test_it_does_not_mistake_another_failure_for_a_request_the_model_cannot_fit(Throwable $throwable): void
    {
        self::assertFalse((new TransientFailureClassifier())->isRequestTooLarge($throwable));
    }

    /** @return iterable<string, array{Throwable}> */
    public static function notRequestTooLargeCases(): iterable
    {
        yield 'plain_400' => [new RuntimeException('HTTP 400 Bad Request')];
        yield 'rate_limit_quota_in_tokens' => [new RuntimeException("This request would exceed your organization's rate limit of 400,000 input tokens per minute")];
        yield 'max_output_tokens_too_large' => [new RuntimeException('max_tokens is too large: 200000. This model supports at most 16384 completion tokens')];
        yield 'unauthorized_401' => [new RuntimeException('HTTP 401 Unauthorized')];
        yield 'request_id_embedding_413' => [new RuntimeException('HTTP 500 Internal Server Error (request id req-413-abc)')];
        yield 'rate_limit_quoting_a_413_token_count' => [new RuntimeException('HTTP 429 Too Many Requests: Rate limit reached on tokens per min. Limit 30000, Used 29800, Requested 413.')];
    }
}
