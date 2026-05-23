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

/**
 * Decides whether an exception thrown by the LLM platform represents a
 * *transient* failure worth retrying (network blip, provider 429/5xx) versus
 * a *non-transient* one (auth error, validation error, account suspended).
 *
 * The classifier walks the entire `previous` chain so wrapper exceptions like
 * `ClientExceptionInterface` carrying an HTTP 429 underneath are still
 * recognized.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
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

    public function isTransient(Throwable $throwable): bool
    {
        $messages = [];
        $current = $throwable;
        while ($current instanceof Throwable) {
            $messages[] = mb_strtolower($current->getMessage());
            $current = $current->getPrevious();
        }

        $joined = implode("\n", $messages);

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
}
