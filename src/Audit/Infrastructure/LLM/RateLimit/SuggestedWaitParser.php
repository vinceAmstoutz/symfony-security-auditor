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

use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Throwable;

/**
 * The waits a rate-limited provider names besides its `Retry-After`, in
 * milliseconds: the one its message asks for (OpenAI's `Please try again in
 * 8.064s.`, Gemini's `Please retry in 41.8s.`) and the time OpenAI says its
 * token window takes to reset (`x-ratelimit-reset-tokens: 6m0s`), whichever
 * is longest; 0 when it names none. OpenAI's bridge hands back the
 * request-window reset as the `Retry-After` hint, which a request over the
 * token limit outlasts. Messages are matched byte for byte, since a
 * provider's message is not always valid UTF-8.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SuggestedWaitParser
{
    private const string TOKEN_WINDOW_RESET_HEADER = 'x-ratelimit-reset-tokens';

    private const string WAIT_IN_A_MESSAGE = '/(?:try again|retry) in \K(?:\d+(?:\.\d+)?(?:ms|h|m|s))+/i';

    private const string WHOLE_DURATION = '/^(?:\d+(?:\.\d+)?(?:ms|h|m|s))+$/';

    private const string DURATION_PART = '/(\d+(?:\.\d+)?)(ms|h|m|s)/';

    public function milliseconds(Throwable $throwable, ?DeferredResult $deferredResult): int
    {
        return max([$this->tokenWindowReset($deferredResult), ...$this->waitsInMessages($throwable)]);
    }

    /**
     * @return list<int>
     */
    private function waitsInMessages(Throwable $throwable): array
    {
        $waits = [];
        for ($current = $throwable; $current instanceof Throwable; $current = $current->getPrevious()) {
            if (1 === preg_match(self::WAIT_IN_A_MESSAGE, $current->getMessage(), $matches)) {
                $waits[] = $this->durationMs($matches[0]);
            }
        }

        return $waits;
    }

    private function tokenWindowReset(?DeferredResult $deferredResult): int
    {
        $response = $deferredResult?->getRawResult()->getObject();
        if (!$response instanceof ResponseInterface) {
            return 0;
        }

        try {
            $reset = $response->getHeaders(false)[self::TOKEN_WINDOW_RESET_HEADER][0] ?? '';
        } catch (TransportExceptionInterface) {
            return 0;
        }

        return 1 === preg_match(self::WHOLE_DURATION, $reset) ? $this->durationMs($reset) : 0;
    }

    private function durationMs(string $duration): int
    {
        preg_match_all(self::DURATION_PART, $duration, $parts, \PREG_SET_ORDER);

        $milliseconds = 0.0;
        foreach ($parts as [, $amount, $unit]) {
            $milliseconds += $this->partMs((float) $amount, $unit);
        }

        return (int) ceil($milliseconds);
    }

    private function partMs(float $amount, string $unit): float
    {
        return $amount * match ($unit) {
            'ms' => 1,
            's' => 1_000,
            'm' => 60_000,
            default => 3_600_000,
        };
    }
}
