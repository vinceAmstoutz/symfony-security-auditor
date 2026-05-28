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
        yield 'http_429' => [new RuntimeException('HTTP 429 Too Many Requests')];
        yield 'http_500' => [new RuntimeException('Server returned HTTP 500')];
        yield 'http_502' => [new RuntimeException('Bad Gateway 502')];
        yield 'http_503' => [new RuntimeException('Service Unavailable (HTTP 503)')];
        yield 'http_504' => [new RuntimeException('Gateway Timeout (504)')];
        yield 'rate_limit_phrasing' => [new RuntimeException('Rate limit exceeded')];
        yield 'timeout_phrasing' => [new RuntimeException('Request timed out after 30s')];
        yield 'temporarily_unavailable' => [new RuntimeException('Provider temporarily unavailable')];
        yield 'connection_reset' => [new RuntimeException('Connection reset by peer')];
        yield 'connection_refused' => [new RuntimeException('Connection refused: localhost:443')];
        yield 'wrapped_transient' => [
            new RuntimeException(
                'API call failed',
                previous: new RuntimeException('underlying: 503 service unavailable'),
            ),
        ];
    }

    #[DataProvider('nonTransientCases')]
    public function test_it_recognizes_non_transient_failures(Throwable $throwable): void
    {
        self::assertFalse((new TransientFailureClassifier())->isTransient($throwable));
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
        yield 'connection_reset' => [new RuntimeException('Connection reset by peer')];
        yield 'http_401_non_transient' => [new RuntimeException('HTTP 401 Unauthorized')];
        yield 'unknown_error' => [new RuntimeException('Something went wrong')];
    }

    /** @return iterable<string, array{Throwable}> */
    public static function nonTransientCases(): iterable
    {
        yield 'http_400_bad_request' => [new RuntimeException('HTTP 400 Bad Request')];
        yield 'http_401_unauthorized' => [new RuntimeException('Unauthorized: 401')];
        yield 'http_403_forbidden' => [new RuntimeException('Forbidden: 403')];
        yield 'http_404_not_found' => [new RuntimeException('Not Found (404)')];
        yield 'http_422_validation' => [new RuntimeException('422 Unprocessable Entity')];
        yield 'invalid_api_key' => [new RuntimeException('Invalid API key provided')];
        yield 'authentication_failed' => [new RuntimeException('authentication failed')];
        yield 'unknown_error_phrasing' => [new RuntimeException('Something went wrong without identifiable signal')];
        yield 'non_transient_wins_over_transient_in_chain' => [
            new RuntimeException('connection reset', previous: new RuntimeException('HTTP 401')),
        ];
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
}
