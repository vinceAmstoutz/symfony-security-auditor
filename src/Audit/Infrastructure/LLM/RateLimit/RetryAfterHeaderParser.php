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
            if (1 === preg_match('/retry-after\s*:\s*(\d+)/i', $current->getMessage(), $matches)) {
                $seconds = (int) $matches[1];
                if ($seconds > 0) {
                    return $seconds;
                }
            }

            $current = $current->getPrevious();
        }

        return null;
    }
}
