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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimit;

use Symfony\AI\Platform\Exception\RateLimitExceededException;
use Throwable;

/**
 * Extracts the server-suggested wait (in seconds) from a 429 throwable chain.
 *
 * Prefers `Symfony\AI\Platform\Exception\RateLimitExceededException::getRetryAfter()`
 * which the platform's `HttpStatusErrorHandlingTrait` populates from the
 * `retry-after` response header. Falls back to a `retry-after: <int>` substring
 * scan over the chained messages when no typed exception is present, covering
 * custom providers that surface the header through a plain `RuntimeException`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RetryAfterHeaderParser
{
    public function parse(Throwable $throwable): ?int
    {
        $current = $throwable;
        while ($current instanceof Throwable) {
            if ($current instanceof RateLimitExceededException) {
                $retryAfter = $current->getRetryAfter();
                if (null !== $retryAfter && $retryAfter > 0) {
                    return $retryAfter;
                }
            }

            $current = $current->getPrevious();
        }

        return $this->parseFromMessage($throwable);
    }

    private function parseFromMessage(Throwable $throwable): ?int
    {
        $current = $throwable;
        while ($current instanceof Throwable) {
            $seconds = $this->secondsFromMessage($current->getMessage());
            if (null !== $seconds) {
                return $seconds;
            }

            $current = $current->getPrevious();
        }

        return null;
    }

    /**
     * Accepts both RFC 7231 `Retry-After` forms: a delta-seconds integer, or
     * an HTTP-date, converted to a delta relative to now.
     */
    private function secondsFromMessage(string $message): ?int
    {
        if (1 === preg_match('/retry-after\s*:\s*(\d+)/i', $message, $matches)) {
            $seconds = (int) $matches[1];

            return $seconds > 0 ? $seconds : null;
        }

        if (1 === preg_match('/retry-after\s*:\s*([A-Za-z]{3},\s*\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT)/i', $message, $matches)) {
            $timestamp = strtotime($matches[1]);
            if (false === $timestamp) {
                return null;
            }

            $seconds = $timestamp - time();

            return $seconds > 0 ? $seconds : null;
        }

        return null;
    }
}
