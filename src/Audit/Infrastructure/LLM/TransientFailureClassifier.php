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

use Symfony\AI\Platform\Exception\ContentFilterException;
use Symfony\AI\Platform\Exception\ExceedContextSizeException;
use Symfony\AI\Platform\Exception\IncompleteStreamException;
use Symfony\AI\Platform\Exception\MalformedToolCallException;
use Symfony\AI\Platform\Exception\MaxOutputTokensException;
use Symfony\AI\Platform\Exception\ModelNotFoundException;
use Symfony\AI\Platform\Exception\RetryableExceptionInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientHttpStatusException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnconvertedAnswerException;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise, see docs/versioning.md */
final readonly class TransientFailureClassifier
{
    private const string MALFORMED_TOOL_CALL_STOP_REASON = 'malformed_tool_call';

    private const string INCOMPLETE_STREAM_STOP_REASON = 'incomplete_stream';

    /** @var list<string> */
    private const array TRANSIENT_STATUS_CODES = ['429', '500', '502', '503', '504', '529'];

    /** @var list<string> */
    private const array TRANSIENT_HINTS = [
        'too many requests',
        'rate limit',
        'rate_limit',
        'timeout',
        'timed out',
        'failed to connect',
        'could not resolve host',
        'failure in name resolution',
        'temporarily unavailable',
        'service unavailable',
        'internal server error',
        'bad gateway',
        'gateway timeout',
        'overloaded',
        'connection reset',
        'connection refused',
        'connection aborted',
        'network is unreachable',
    ];

    /** @var list<string> */
    private const array CONNECTION_CUT_HINTS = [
        'unexpected eof while reading',
        'eof occurred in violation of protocol',
        'ssl_error_syscall',
        'recv failure',
        'failure when receiving data from the peer',
        'failed sending data to the peer',
        'curl error 18',
        'transfer closed with',
        'transferred a partial file',
        'was not closed cleanly',
        'framing layer',
        'empty reply from server',
        'broken pipe',
        'connection closed by peer',
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
    private const array QUOTA_EXHAUSTED_HINTS = [
        'insufficient_quota',
        'exceeded your current quota',
    ];

    /** @var list<string> */
    private const array SUGGESTED_WAIT_HINTS = [
        'retry in',
        'retry after',
        'try again in',
    ];

    /** @var list<string> */
    private const array RATE_LIMIT_STATUS_CODES = ['429'];

    private const int RATE_LIMIT_STATUS = 429;

    /** @var list<string> */
    private const array REQUEST_TOO_LARGE_STATUS_CODES = ['413'];

    /** @var list<string> */
    private const array REQUEST_TOO_LARGE_HINTS = [
        'prompt is too long',
        'context length',
        'context_length',
        'too many tokens',
        'exceeds the maximum number of tokens',
        'input is too long',
        'too large for model',
        'request_too_large',
        'request too large',
        'context window',
        'max_model_len',
        'exceed context limit',
        'exceeds the available context size',
        'payload too large',
        'request entity too large',
    ];

    private const string UNKNOWN_MODEL_PATTERN = '/model_not_found|not_found_error.*\bmodel\b|\bmodel.*(?:not found|does not exist)/';

    /** @var list<string> */
    private const array RATE_LIMIT_HINTS = [
        'too many requests',
        'rate limit',
        'rate_limit',
    ];

    /** @var list<string> */
    private const array OUTPUT_LIMIT_HINTS = [
        'unsupported finish reason "max_tokens"',
    ];

    /** @var list<string> */
    private const array CONTENT_FILTER_HINTS = [
        'unsupported finish reason "content_filter"',
        'incomplete (content_filter)',
    ];

    /** @var list<string> */
    private const array EMPTY_CONTENT_HINTS = [
        'does not contain any content',
        'response does not contain',
        'no content blocks',
        'no completions found',
    ];

    /**
     * Returns true for a failure worth retrying, a malformed tool call
     * included; a 429 that says the billing quota is used up is not one.
     */
    public function isTransient(Throwable $throwable): bool
    {
        return !$this->isQuotaExhausted($throwable) && $this->readsAsTransient($throwable);
    }

    /**
     * Returns true for a 429 naming an exhausted quota (OpenAI), unless it
     * suggests a wait, as a Gemini rate limit worded the same way does.
     */
    private function isQuotaExhausted(Throwable $throwable): bool
    {
        $joined = u($this->joinMessages($throwable));

        return $joined->containsAny(self::QUOTA_EXHAUSTED_HINTS) && !$joined->containsAny(self::SUGGESTED_WAIT_HINTS);
    }

    private function readsAsTransient(Throwable $throwable): bool
    {
        if ($this->hasInChain($throwable, RetryableExceptionInterface::class) || $this->hasInChain($throwable, MalformedToolCallException::class) || $this->hasInChain($throwable, TransientHttpStatusException::class)) {
            return true;
        }

        if ($this->isRateLimit($throwable) || $this->isConnectionCut($throwable)) {
            return true;
        }

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
     * Returns the stop reason `LLMResponse` gives an answer cut off by the
     * output limit (`length`), withheld by a content filter (`content-filter`)
     * or empty (`empty_content`) that the provider reported as a failure; null
     * for any other failure. The stop reason an `UnconvertedAnswerException`
     * read from the raw answer decides, except for a request refused with a
     * client error, which is read by the bridge's message alone. A status that
     * clears on its own (`TransientHttpStatusException`) is never degraded.
     */
    public function degradedStopReason(Throwable $throwable): ?string
    {
        if ($this->hasInChain($throwable, TransientHttpStatusException::class)) {
            return null;
        }

        $unconvertedAnswerException = $this->firstInChain($throwable, UnconvertedAnswerException::class);
        if ($unconvertedAnswerException instanceof UnconvertedAnswerException && !$unconvertedAnswerException->refusedWithClientError) {
            return $unconvertedAnswerException->stopReason;
        }

        return $this->degradedStopReasonTheBridgeNamed($throwable);
    }

    private function degradedStopReasonTheBridgeNamed(Throwable $throwable): ?string
    {
        $joined = $this->joinMessages($throwable);

        if ($this->hasInChain($throwable, MaxOutputTokensException::class) || u($joined)->containsAny(self::OUTPUT_LIMIT_HINTS)) {
            return 'length';
        }

        if ($this->hasInChain($throwable, ContentFilterException::class) || u($joined)->containsAny(self::CONTENT_FILTER_HINTS)) {
            return 'content-filter';
        }

        return $this->isEmptyContent($throwable) ? 'empty_content' : null;
    }

    /**
     * Returns true for a tool call the output cap cut off, which a higher cap
     * lets through.
     */
    public function isToolCallCutByTheOutputCap(Throwable $throwable): bool
    {
        return $this->hasInChain($throwable, MaxOutputTokensException::class);
    }

    /**
     * Returns why a failed call was still billed: a degraded stop reason,
     * `malformed_tool_call` or `incomplete_stream`. Null for a call the
     * provider never answered or refused with a client error, which spent
     * nothing.
     */
    public function billedStopReason(Throwable $throwable): ?string
    {
        if (true === $this->firstInChain($throwable, UnconvertedAnswerException::class)?->refusedWithClientError) {
            return null;
        }

        return $this->degradedStopReason($throwable)
            ?? ($this->hasInChain($throwable, MalformedToolCallException::class) ? self::MALFORMED_TOOL_CALL_STOP_REASON : null)
            ?? ($this->hasInChain($throwable, IncompleteStreamException::class) ? self::INCOMPLETE_STREAM_STOP_REASON : null);
    }

    /**
     * Returns true when a symfony/ai converter reports an answer with no
     * content, which callers turn into an empty `LLMResponse` instead of
     * aborting the audit.
     */
    public function isEmptyContent(Throwable $throwable): bool
    {
        return u($this->joinMessages($throwable))->containsAny(self::EMPTY_CONTENT_HINTS);
    }

    /**
     * Returns true when the provider refuses a prompt larger than the model's
     * window, by its wording or an HTTP 413, so the caller splits the work
     * instead of retrying it. A 413 in a rate-limit answer or a connection cut
     * is a token count, not a status.
     */
    public function isRequestTooLarge(Throwable $throwable): bool
    {
        if ($this->hasInChain($throwable, ExceedContextSizeException::class) || true === $this->firstInChain($throwable, UnconvertedAnswerException::class)?->refusedAsTooLarge) {
            return true;
        }

        $joined = $this->joinMessages($throwable);

        return u($joined)->containsAny(self::REQUEST_TOO_LARGE_HINTS)
            || (!$this->isRateLimit($throwable) && !$this->isConnectionCut($throwable) && $this->containsStatusCode($joined, self::REQUEST_TOO_LARGE_STATUS_CODES));
    }

    /**
     * Returns true when the provider, or the platform's model catalog, does not
     * know the model the call names.
     */
    public function isUnknownModel(Throwable $throwable): bool
    {
        return $this->hasInChain($throwable, ModelNotFoundException::class)
            || 1 === preg_match(self::UNKNOWN_MODEL_PATTERN, $this->joinMessages($throwable));
    }

    public function isRateLimit(Throwable $throwable): bool
    {
        $joined = $this->joinMessages($throwable);

        if (u($joined)->containsAny(self::RATE_LIMIT_HINTS) || self::RATE_LIMIT_STATUS === $this->firstInChain($throwable, TransientHttpStatusException::class)?->status) {
            return true;
        }

        return $this->containsStatusCode($joined, self::RATE_LIMIT_STATUS_CODES);
    }

    /**
     * Returns true for a call cut before its answer ended, which the provider
     * may bill beyond the usage it reported.
     */
    public function isCutMidAnswer(Throwable $throwable): bool
    {
        return $this->isConnectionCut($throwable);
    }

    /**
     * Returns true when the peer hung up mid-response or a stream ended before
     * its terminal event. Such a message carries no HTTP status, so none of
     * its numbers is read as one.
     */
    private function isConnectionCut(Throwable $throwable): bool
    {
        return $this->hasInChain($throwable, IncompleteStreamException::class) || u($this->joinMessages($throwable))->containsAny(self::CONNECTION_CUT_HINTS);
    }

    /**
     * @param class-string<Throwable> $exceptionClass
     */
    private function hasInChain(Throwable $throwable, string $exceptionClass): bool
    {
        return $this->firstInChain($throwable, $exceptionClass) instanceof Throwable;
    }

    /**
     * @template T of Throwable
     *
     * @param class-string<T> $exceptionClass
     *
     * @return T|null
     */
    private function firstInChain(Throwable $throwable, string $exceptionClass): ?Throwable
    {
        $current = $throwable;
        while ($current instanceof Throwable) {
            if ($current instanceof $exceptionClass) {
                return $current;
            }

            $current = $current->getPrevious();
        }

        return null;
    }

    /**
     * Skips each `UnconvertedAnswerException`, which only restates the bridge
     * failure it wraps.
     */
    private function joinMessages(Throwable $throwable): string
    {
        $messages = [];
        $current = $throwable;
        while ($current instanceof Throwable) {
            if (!$current instanceof UnconvertedAnswerException) {
                $messages[] = u($current->getMessage())->lower()->toString();
            }

            $current = $current->getPrevious();
        }

        return implode("\n", $messages);
    }

    /**
     * Ignores a code inside a hyphenated identifier (`abc-500-xyz`) or a
     * decimal or thousands-separated number.
     *
     * @param list<string> $codes
     */
    private function containsStatusCode(string $joined, array $codes): bool
    {
        return 1 === preg_match(\sprintf('/(?<![\w-])(?<!\d[,.])(?:%s)(?![\w-])(?![,.]\d)/', implode('|', $codes)), $joined);
    }
}
