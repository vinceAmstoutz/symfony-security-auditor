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
}
