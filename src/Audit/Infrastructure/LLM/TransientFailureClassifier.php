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
use Symfony\AI\Platform\Exception\MalformedToolCallException;
use Symfony\AI\Platform\Exception\MaxOutputTokensException;
use Symfony\AI\Platform\Exception\ServerException;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnconvertedAnswerException;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class TransientFailureClassifier
{
    private const string MALFORMED_TOOL_CALL_STOP_REASON = 'malformed_tool_call';

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
    ];

    /**
     * A tool call whose arguments are not valid JSON is a sampling glitch, not
     * a rejected request: asking again usually gets a well-formed call. A 429
     * that says the billing quota is used up is the opposite: it repeats until
     * funds are added, however long the run waits.
     */
    public function isTransient(Throwable $throwable): bool
    {
        return !$this->isQuotaExhausted($throwable) && $this->readsAsTransient($throwable);
    }

    /**
     * OpenAI answers an exhausted billing quota with a 429 (`insufficient_quota`,
     * `You exceeded your current quota, please check your plan and billing
     * details.`), which reads as a rate limit. Gemini words a per-minute rate
     * limit the same way but adds the wait (`Please retry in 41.8s.`), and
     * that one clears, so a message that suggests a wait is a rate limit.
     */
    private function isQuotaExhausted(Throwable $throwable): bool
    {
        $joined = u($this->joinMessages($throwable));

        return $joined->containsAny(self::QUOTA_EXHAUSTED_HINTS) && !$joined->containsAny(self::SUGGESTED_WAIT_HINTS);
    }

    private function readsAsTransient(Throwable $throwable): bool
    {
        if ($throwable instanceof ServerException || $this->hasInChain($throwable, MalformedToolCallException::class)) {
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
     * The stop reason `LLMResponse` gives the same outcome when a provider
     * delivers it as a response rather than a failure: the model answered, but
     * with nothing usable — cut off by the output limit, withheld by a content
     * filter, or empty. A bridge reports the first two as a typed exception or
     * as a plain one naming the provider's own reason (the generic bridge's
     * `Unsupported finish reason "content_filter".`, the Responses API's
     * `response is incomplete (content_filter)`, Cohere's `Unsupported finish
     * reason "MAX_TOKENS".`), and an answer it failed to convert can only
     * show it in its raw answer (`UnconvertedAnswerException`). That raw
     * answer has the last word: a request it shows refused as too large was
     * never answered, whatever the bridge made of the body that came with the
     * refusal (`Response does not contain choices.`). A request refused with
     * any other client error is read by the bridge's message alone, as the
     * same failure without a status: an empty answer there, a failure that
     * aborts the run where the bridge named one. Null for any other failure.
     */
    public function degradedStopReason(Throwable $throwable): ?string
    {
        $unconvertedAnswerException = $this->firstInChain($throwable, UnconvertedAnswerException::class);
        if ($unconvertedAnswerException instanceof UnconvertedAnswerException && !$unconvertedAnswerException->refusedWithClientError) {
            return $unconvertedAnswerException->stopReason;
        }

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
     * Why a call that failed was still billed: the provider took the request
     * in and answered it, with nothing usable (the degraded stop reason) or
     * with a tool call whose arguments are not valid JSON
     * (`malformed_tool_call`). Null for a failure it never answered, which
     * spent nothing the budget or the rate window has to hold, and neither
     * does a request it refused with a client error: nothing was served.
     */
    public function billedStopReason(Throwable $throwable): ?string
    {
        if (true === $this->firstInChain($throwable, UnconvertedAnswerException::class)?->refusedWithClientError) {
            return null;
        }

        return $this->degradedStopReason($throwable)
            ?? ($this->hasInChain($throwable, MalformedToolCallException::class) ? self::MALFORMED_TOOL_CALL_STOP_REASON : null);
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
     * Recognises a provider refusing the request because the prompt is larger
     * than the model's window (Anthropic's `prompt is too long` and `input
     * length and max_tokens exceed context limit`, the OpenAI-compatible
     * `maximum context length` / `context_length_exceeded`, Mistral's `too
     * large for model`, Gemini's `exceeds the maximum number of tokens`,
     * Bedrock's `Input is too long`, llama.cpp's `exceeds the available context
     * size`, or an HTTP 413 — a gateway's `Payload Too Large`, or the 413
     * status `UnconvertedAnswerException` read from an answer the bridge
     * could not decode). Retrying the same prompt cannot succeed, but a
     * smaller one can — so callers split the work instead of retrying or
     * aborting. A 413 inside a rate-limit answer is a token count, not a
     * status, and so is one in a connection cut off mid-response.
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

    /**
     * The peer hung up while the response was being read — in curl's wording
     * as symfony/http-client relays it, `Transfer closed with 512 bytes
     * remaining to read for "https://…".` and the like. No HTTP status came
     * back, so a byte count, an HTTP/2 stream id or the URL in that message is
     * never a status code, and it is retried before any is looked for.
     */
    private function isConnectionCut(Throwable $throwable): bool
    {
        return u($this->joinMessages($throwable))->containsAny(self::CONNECTION_CUT_HINTS);
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
     * An `UnconvertedAnswerException` only restates the message of the bridge
     * failure it wraps, so the classification reads that one.
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
     * `\b` treats a hyphen as a boundary the same as whitespace, so a status
     * code embedded in a hyphenated identifier (a request id like
     * `abc-500-xyz`, a model name like `gpt-4o-500`) matched as confidently as
     * a genuine status code. The `[\w-]` lookaround excludes that case
     * alongside the existing decimal/thousands-separator exclusion.
     *
     * @param list<string> $codes
     */
    private function containsStatusCode(string $joined, array $codes): bool
    {
        return 1 === preg_match(\sprintf('/(?<![\w-])(?<!\d[,.])(?:%s)(?![\w-])(?![,.]\d)/', implode('|', $codes)), $joined);
    }
}
