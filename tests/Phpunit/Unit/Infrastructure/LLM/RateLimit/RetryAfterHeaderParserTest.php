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

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\AI\Platform\Exception\RateLimitExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit\RetryAfterHeaderParser;

final class RetryAfterHeaderParserTest extends TestCase
{
    public function test_extracts_retry_after_seconds_from_symfony_ai_exception(): void
    {
        $rateLimitExceededException = new RateLimitExceededException(retryAfter: 42);

        $retryAfterHeaderParser = new RetryAfterHeaderParser();

        self::assertSame(42, $retryAfterHeaderParser->parse($rateLimitExceededException));
    }

    public function test_extracts_retry_after_when_exception_is_wrapped(): void
    {
        $rateLimitExceededException = new RateLimitExceededException(retryAfter: 90);
        $runtimeException = new RuntimeException('boom', previous: $rateLimitExceededException);

        $retryAfterHeaderParser = new RetryAfterHeaderParser();

        self::assertSame(90, $retryAfterHeaderParser->parse($runtimeException));
    }

    public function test_returns_null_when_symfony_ai_exception_has_no_retry_after(): void
    {
        $rateLimitExceededException = new RateLimitExceededException();

        $retryAfterHeaderParser = new RetryAfterHeaderParser();

        self::assertNull($retryAfterHeaderParser->parse($rateLimitExceededException));
    }

    public function test_typed_exception_with_zero_retry_after_returns_null(): void
    {
        // retry-after: 0 is a degenerate hint — the parser must treat it as
        // "no useful hint" so the caller's exponential backoff kicks in
        // instead of an immediate (potentially-stampeding) retry.
        $rateLimitExceededException = new RateLimitExceededException(retryAfter: 0);

        $retryAfterHeaderParser = new RetryAfterHeaderParser();

        self::assertNull($retryAfterHeaderParser->parse($rateLimitExceededException));
    }

    public function test_returns_null_when_no_rate_limit_exception_in_chain(): void
    {
        $runtimeException = new RuntimeException('connection reset');

        $retryAfterHeaderParser = new RetryAfterHeaderParser();

        self::assertNull($retryAfterHeaderParser->parse($runtimeException));
    }

    public function test_parses_retry_after_seconds_from_message_when_no_typed_exception(): void
    {
        $runtimeException = new RuntimeException('HTTP 429: retry-after: 17');

        $retryAfterHeaderParser = new RetryAfterHeaderParser();

        self::assertSame(17, $retryAfterHeaderParser->parse($runtimeException));
    }

    public function test_message_extraction_is_case_insensitive(): void
    {
        // Real HTTP responses surface the header as `Retry-After:` (titlecase)
        // while symfony/ai exception messages tend to be lowercase. The regex
        // must match both — without the `i` flag, titlecase variants would
        // silently fall through.
        $runtimeException = new RuntimeException('HTTP 429: Retry-After: 23');

        $retryAfterHeaderParser = new RetryAfterHeaderParser();

        self::assertSame(23, $retryAfterHeaderParser->parse($runtimeException));
    }

    public function test_message_extraction_ignores_zero_and_negative_values(): void
    {
        $runtimeException = new RuntimeException('retry-after: 0');

        $retryAfterHeaderParser = new RetryAfterHeaderParser();

        self::assertNull($retryAfterHeaderParser->parse($runtimeException));
    }

    public function test_typed_exception_wins_over_message_text(): void
    {
        // Wrapper's message claims 999 but the typed cause says 5 — typed cause wins.
        $rateLimitExceededException = new RateLimitExceededException(retryAfter: 5);
        $runtimeException = new RuntimeException('retry-after: 999', previous: $rateLimitExceededException);

        $retryAfterHeaderParser = new RetryAfterHeaderParser();

        self::assertSame(5, $retryAfterHeaderParser->parse($runtimeException));
    }
}
