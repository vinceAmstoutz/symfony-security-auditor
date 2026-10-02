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

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class TransientFailureClassifier
{
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
        'unexpected eof while reading',
        'eof occurred in violation of protocol',
        'recv failure',
        'failed sending data to the peer',
        'curl error 18',
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
    ];

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

    /**
     * A tool call whose arguments are not valid JSON is a sampling glitch, not
     * a rejected request: asking again usually gets a well-formed call.
     */
    public function isTransient(Throwable $throwable): bool
    {
        if ($throwable instanceof ServerException || $this->hasInChain($throwable, MalformedToolCallException::class)) {
            return true;
        }

        if ($this->isRateLimit($throwable)) {
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
     * filter, or empty. Null for any other failure.
     */
    public function degradedStopReason(Throwable $throwable): ?string
    {
        if ($this->hasInChain($throwable, MaxOutputTokensException::class)) {
            return 'length';
        }

        if ($this->hasInChain($throwable, ContentFilterException::class)) {
            return 'content-filter';
        }

        return $this->isEmptyContent($throwable) ? 'empty_content' : null;
    }

    /**
     * A degraded answer is one the provider took in and answered, so its
     * input counts against the rate window as it does against the budget; any
     * other failure released nothing the window has to hold.
     */
    public function inputTokensTakenIn(Throwable $throwable, int $estimatedInputTokens): int
    {
        return null !== $this->degradedStopReason($throwable) ? $estimatedInputTokens : 0;
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
     * size`, or an HTTP 413). Retrying the same prompt cannot succeed, but a
     * smaller one can — so callers split the work instead of retrying or
     * aborting. A 413 inside a rate-limit answer is a token count, not a
     * status.
     */
    public function isRequestTooLarge(Throwable $throwable): bool
    {
        if ($this->hasInChain($throwable, ExceedContextSizeException::class)) {
            return true;
        }

        $joined = $this->joinMessages($throwable);

        return u($joined)->containsAny(self::REQUEST_TOO_LARGE_HINTS)
            || (!$this->isRateLimit($throwable) && $this->containsStatusCode($joined, self::REQUEST_TOO_LARGE_STATUS_CODES));
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
     * @param class-string<Throwable> $exceptionClass
     */
    private function hasInChain(Throwable $throwable, string $exceptionClass): bool
    {
        $current = $throwable;
        while ($current instanceof Throwable) {
            if ($current instanceof $exceptionClass) {
                return true;
            }

            $current = $current->getPrevious();
        }

        return false;
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
