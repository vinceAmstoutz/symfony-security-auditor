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
 * The prompt alone exceeds what the model can take in. Unlike other
 * `LLMProviderException`s it does not abort the audit: the chunk is split and
 * each half retried. A single file that does not fit is recorded as errored.
 *
 * Not final: `RateLimitRequestTooLargeException` extends it for a request
 * larger than the configured rate-limit window.
 */
class LLMRequestTooLargeException extends LLMProviderException
{
    public static function fromProviderRejection(Throwable $throwable): self
    {
        return new self(\sprintf('The model cannot fit the request: %s', ProviderMessageRedactor::redact($throwable->getMessage())), previous: $throwable);
    }
}
