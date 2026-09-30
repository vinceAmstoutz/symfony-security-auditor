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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception;

use Throwable;

/**
 * The provider refused a request because the prompt alone exceeds what the
 * model can take in — the one `LLMProviderException` that does not repeat on
 * every call, since the same model answers a smaller prompt. The chunk
 * analyzers catch it to split the chunk and retry each half instead of
 * aborting the audit; a single file the model cannot fit is recorded as
 * errored and the run goes on.
 *
 * Not final: `RateLimitRequestTooLargeException` (Infrastructure) extends it
 * for a request whose estimated input exceeds the configured rate-limit
 * window — which no amount of waiting fixes either.
 */
class LLMRequestTooLargeException extends LLMProviderException
{
    public static function fromProviderRejection(Throwable $throwable): self
    {
        return new self(\sprintf('The model cannot fit the request: %s', $throwable->getMessage()), previous: $throwable);
    }
}
