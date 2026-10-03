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
use Symfony\AI\Platform\Exception\BadRequestException;
use Symfony\AI\Platform\Exception\ContentFilterException;
use Symfony\AI\Platform\Exception\ExceedContextSizeException;
use Symfony\AI\Platform\Exception\MalformedToolCallException;
use Symfony\AI\Platform\Exception\MaxOutputTokensException;
use Symfony\AI\Platform\Exception\RuntimeException as PlatformRuntimeException;
use Symfony\AI\Platform\Exception\ServerException;
use Symfony\Component\HttpClient\Exception\TransportException;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnconvertedAnswerException;
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
        yield 'openssl_unexpected_eof_while_reading' => [new RuntimeException('OpenSSL SSL_read: OpenSSL/3.5.7: error:0A000126:SSL routines::unexpected eof while reading, errno 0 for "https://example.com/v1/chat/completions".')];
        yield 'php_openssl_eof_in_violation_of_protocol' => [new RuntimeException('SSL: eof occurred in violation of protocol')];
        yield 'curl_recv_failure' => [new RuntimeException('cURL error 56: Recv failure')];
        yield 'curl_send_failure' => [new RuntimeException('cURL error 55: Failed sending data to the peer')];
        yield 'curl_error_18_partial_file' => [new RuntimeException('cURL error 18: end of response with 0 bytes read')];
        yield 'empty_reply_from_server' => [new RuntimeException('Empty reply from server')];
        yield 'broken_pipe' => [new RuntimeException('Broken pipe')];
        yield 'connection_closed_by_peer' => [new RuntimeException('Connection closed by peer')];
        yield 'symfony_transfer_closed_with_bytes_remaining' => [self::transportFailure('Transfer closed with 1234 bytes remaining to read')];
        yield 'symfony_transfer_closed_with_outstanding_read_data' => [self::transportFailure('Transfer closed with outstanding read data remaining')];
        yield 'symfony_transferred_a_partial_file' => [self::transportFailure('Transferred a partial file')];
        yield 'symfony_openssl_1_1_eof' => [self::transportFailure('OpenSSL SSL_read: SSL_ERROR_SYSCALL, errno 0')];
        yield 'symfony_libressl_reset' => [self::transportFailure('LibreSSL SSL_read: SSL_ERROR_SYSCALL, errno 54')];
        yield 'symfony_http2_stream_not_closed_cleanly' => [self::transportFailure('HTTP/2 stream 1 was not closed cleanly: INTERNAL_ERROR (err 2)')];
        yield 'symfony_http2_framing_layer' => [self::transportFailure('Error in the HTTP2 framing layer')];
        yield 'symfony_http2_stream_framing_layer' => [self::transportFailure('Stream error in the HTTP/2 framing layer')];
        yield 'symfony_failure_when_receiving_data' => [self::transportFailure('Failure when receiving data from the peer')];
        yield 'symfony_openssl_3_unexpected_eof' => [self::transportFailure('OpenSSL SSL_read: OpenSSL/3.5.7: error:0A000126:SSL routines::unexpected eof while reading, errno 0')];
        yield 'symfony_recv_failure' => [self::transportFailure('Recv failure: Connection reset by peer')];
        yield 'symfony_failed_sending_data' => [self::transportFailure('Failed sending data to the peer')];
        yield 'symfony_empty_reply_from_server' => [self::transportFailure('Empty reply from server')];
        yield 'symfony_send_failure_broken_pipe' => [self::transportFailure('Send failure: Broken pipe')];
    }

    #[DataProvider('connectionCutCarryingAStatusLikeTokenCases')]
    public function test_a_connection_cut_off_mid_response_is_retried_whatever_number_or_word_its_message_carries(Throwable $throwable): void
    {
        self::assertTrue((new TransientFailureClassifier())->isTransient($throwable));
    }

    /** @return iterable<string, array{Throwable}> */
    public static function connectionCutCarryingAStatusLikeTokenCases(): iterable
    {
        yield 'byte_count_equal_to_a_non_transient_status' => [self::transportFailure('Transfer closed with 404 bytes remaining to read')];
        yield 'http2_stream_id_equal_to_a_non_transient_status' => [self::transportFailure('HTTP/2 stream 401 was not closed cleanly: INTERNAL_ERROR (err 2)')];
        yield 'url_path_segment_equal_to_a_non_transient_status' => [new TransportException('OpenSSL SSL_read: OpenSSL/3.5.7: error:0A000126:SSL routines::unexpected eof while reading, errno 0 for "https://gw.example.com/403/v1/chat/completions".')];
        yield 'url_host_carrying_a_non_transient_word' => [new TransportException('Recv failure: Connection reset by peer for "https://authentication-gw.example.com/v1/chat/completions".')];
    }

    private static function transportFailure(string $curlError): TransportException
    {
        return new TransportException(\sprintf('%s for "https://gw.example.com/v1/chat/completions".', $curlError));
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
        yield 'symfony_client_error_status' => [new RuntimeException('HTTP 401 returned for "https://gw.example.com/v1/chat/completions".')];
        yield 'symfony_untrusted_certificate' => [self::transportFailure('SSL certificate problem: unable to get local issuer certificate')];
        yield 'symfony_tls_alert_while_reading' => [self::transportFailure('OpenSSL SSL_read: error:0A000412:SSL routines::sslv3 alert bad certificate, errno 0')];
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
        yield 'generic_bridge_unsupported_content_filter_finish_reason' => [new PlatformRuntimeException('Unsupported finish reason "content_filter".'), 'content-filter'];
        yield 'responses_api_incomplete_for_the_content_filter' => [new PlatformRuntimeException('Responses API response is incomplete (content_filter) and contains no content.'), 'content-filter'];
        yield 'cohere_unsupported_max_tokens_finish_reason' => [new PlatformRuntimeException('Unsupported finish reason "MAX_TOKENS".'), 'length'];
        yield 'unsupported_finish_reason_that_cuts_nothing_short' => [new PlatformRuntimeException('Unsupported finish reason "ERROR".'), null];
        yield 'responses_api_incomplete_for_another_reason' => [new PlatformRuntimeException('Responses API response is incomplete (unknown) and contains no content.'), null];
        yield 'answer_its_raw_answer_shows_filtered' => [UnconvertedAnswerException::cutShort(new BadRequestException('The response was filtered'), 'content-filter'), 'content-filter'];
        yield 'answer_its_raw_answer_shows_cut_off_beneath_a_wrapper' => [new RuntimeException('call failed', previous: UnconvertedAnswerException::cutShort(new MalformedToolCallException('bad arguments'), 'length')), 'length'];
        yield 'request_its_raw_answer_shows_refused_as_too_large' => [UnconvertedAnswerException::refusedAsTooLarge(new RuntimeException('Syntax error')), null];
    }

    #[DataProvider('billedStopReasonCases')]
    public function test_it_names_why_a_failed_call_the_provider_answered_was_still_billed(Throwable $throwable, ?string $expectedStopReason): void
    {
        self::assertSame($expectedStopReason, (new TransientFailureClassifier())->billedStopReason($throwable));
    }

    /** @return iterable<string, array{Throwable, ?string}> */
    public static function billedStopReasonCases(): iterable
    {
        yield 'answer_cut_off_by_the_output_limit' => [new MaxOutputTokensException('cut off'), 'length'];
        yield 'answer_withheld_by_a_content_filter' => [new ContentFilterException('blocked'), 'content-filter'];
        yield 'tool_call_with_malformed_arguments' => [new MalformedToolCallException('bad arguments'), 'malformed_tool_call'];
        yield 'wrapped_tool_call_with_malformed_arguments' => [new RuntimeException('call failed', previous: new MalformedToolCallException('bad arguments')), 'malformed_tool_call'];
        yield 'tool_call_its_raw_answer_shows_cut_off' => [UnconvertedAnswerException::cutShort(new MalformedToolCallException('bad arguments'), 'length'), 'length'];
        yield 'failure_the_provider_never_answered' => [new RuntimeException('HTTP 503 Service Unavailable'), null];
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
        yield 'http2_413_without_a_reason_phrase' => [new RuntimeException('HTTP/2 413  returned for "https://gw.example.com/v1/chat/completions".')];
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
        yield 'generic_bridge_relaying_a_gateway_413_body' => [new PlatformRuntimeException('Error "-"-- (-): "Payload too large".')];
        yield 'gateway_413_reason_phrase' => [new RuntimeException('Request Entity Too Large')];
        yield 'gateway_413_its_raw_answer_shows' => [UnconvertedAnswerException::refusedAsTooLarge(new RuntimeException('Syntax error for "https://gw.example.com/v1/chat/completions".'))];
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
        yield 'connection_cut_with_413_bytes_remaining' => [self::transportFailure('Transfer closed with 413 bytes remaining to read')];
        yield 'connection_cut_on_http2_stream_413' => [self::transportFailure('HTTP/2 stream 413 was not closed cleanly: INTERNAL_ERROR (err 2)')];
    }

    public function test_it_does_not_mistake_an_answer_its_raw_answer_shows_was_cut_short_for_a_request_the_model_cannot_fit(): void
    {
        $unconvertedAnswerException = UnconvertedAnswerException::cutShort(new BadRequestException('The response was filtered'), 'content-filter');

        self::assertFalse((new TransientFailureClassifier())->isRequestTooLarge($unconvertedAnswerException));
    }
}
