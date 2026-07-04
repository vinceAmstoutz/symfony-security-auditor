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

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class TransientFailureClassifier
{
    /** @var list<string> */
    private const array TRANSIENT_STATUS_CODES = ['429', '500', '502', '503', '504'];

    /** @var list<string> */
    private const array TRANSIENT_HINTS = [
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
    private const array NON_TRANSIENT_STATUS_CODES = ['400', '401', '403', '404', '422'];

    /** @var list<string> */
    private const array NON_TRANSIENT_HINTS = [
        'invalid api key',
        'authentication',
        'unauthorized',
        'forbidden',
        'not found',
        'invalid request',
    ];

    /** @var list<string> */
    private const array RATE_LIMIT_STATUS_CODES = ['429'];

    /** @var list<string> */
    private const array RATE_LIMIT_HINTS = [
        'too many requests',
        'rate limit',
        'rate_limit',
    ];

    /** @var list<string> */
    private const array EMPTY_CONTENT_HINTS = [
        'does not contain any content',
        'response does not contain',
        'no content blocks',
    ];

    public function isTransient(Throwable $throwable): bool
    {
        $joined = $this->joinMessages($throwable);

        if (u($joined)->containsAny(self::NON_TRANSIENT_HINTS) || $this->containsStatusCode($joined, self::NON_TRANSIENT_STATUS_CODES)) {
            return false;
        }

        if (u($joined)->containsAny(self::TRANSIENT_HINTS)) {
            return true;
        }

        return $this->containsStatusCode($joined, self::TRANSIENT_STATUS_CODES);
    }

    /**
     * Recognises framework-level "the LLM returned no content blocks" errors
     * raised by symfony/ai converters when the model responds with an empty
     * content array. Such responses are not a transport or auth failure —
     * the call succeeded, the model chose to say nothing — so they must not
     * abort the audit. Callers translate this into an empty `LLMResponse`
     * and continue.
     */
    public function isEmptyContent(Throwable $throwable): bool
    {
        return u($this->joinMessages($throwable))->containsAny(self::EMPTY_CONTENT_HINTS);
    }

    /**
     * Returns true when the exception indicates a rate-limit response (HTTP 429).
     * Used by `SymfonyAiLLMClient` to select the rate-limit-specific retry delay
     * rather than the regular exponential backoff.
     */
    public function isRateLimit(Throwable $throwable): bool
    {
        $joined = $this->joinMessages($throwable);

        if (u($joined)->containsAny(self::RATE_LIMIT_HINTS)) {
            return true;
        }

        return $this->containsStatusCode($joined, self::RATE_LIMIT_STATUS_CODES);
    }

    private function joinMessages(Throwable $throwable): string
    {
        $messages = [];
        $current = $throwable;
        while ($current instanceof Throwable) {
            $messages[] = u($current->getMessage())->lower()->toString();
            $current = $current->getPrevious();
        }

        return implode("\n", $messages);
    }

    /**
     * @param list<string> $codes
     */
    private function containsStatusCode(string $joined, array $codes): bool
    {
        return 1 === preg_match('/\b(?:'.implode('|', $codes).')\b/', $joined);
    }
}
