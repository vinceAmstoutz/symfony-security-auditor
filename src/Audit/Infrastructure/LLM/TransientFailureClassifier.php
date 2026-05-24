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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM;

use Throwable;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class TransientFailureClassifier
{
    /** @var list<string> */
    private const array TRANSIENT_HINTS = [
        '429',
        '500',
        '502',
        '503',
        '504',
        'too many requests',
        'rate limit',
        'rate_limit',
        'timeout',
        'timed out',
        'temporarily unavailable',
        'service unavailable',
        'internal server error',
        'bad gateway',
        'gateway timeout',
        'connection reset',
        'connection refused',
        'connection aborted',
        'network is unreachable',
    ];

    /** @var list<string> */
    private const array NON_TRANSIENT_HINTS = [
        '400',
        '401',
        '403',
        '404',
        '422',
        'invalid api key',
        'authentication',
        'unauthorized',
        'forbidden',
        'not found',
        'invalid request',
    ];

    /** @var list<string> */
    private const array RATE_LIMIT_HINTS = [
        '429',
        'too many requests',
        'rate limit',
        'rate_limit',
    ];

    public function isTransient(Throwable $throwable): bool
    {
        $joined = $this->joinMessages($throwable);

        foreach (self::NON_TRANSIENT_HINTS as $hint) {
            if (str_contains($joined, $hint)) {
                return false;
            }
        }

        foreach (self::TRANSIENT_HINTS as $hint) {
            if (str_contains($joined, $hint)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true when the exception indicates a rate-limit response (HTTP 429).
     * Used by `SymfonyAiLLMClient` to select the rate-limit-specific retry delay
     * rather than the regular exponential backoff.
     */
    public function isRateLimit(Throwable $throwable): bool
    {
        $joined = $this->joinMessages($throwable);

        foreach (self::RATE_LIMIT_HINTS as $hint) {
            if (str_contains($joined, $hint)) {
                return true;
            }
        }

        return false;
    }

    private function joinMessages(Throwable $throwable): string
    {
        $messages = [];
        $current = $throwable;
        while ($current instanceof Throwable) {
            $messages[] = strtolower($current->getMessage());
            $current = $current->getPrevious();
        }

        return implode("\n", $messages);
    }
}
