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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception;

use RuntimeException;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\ProviderMessageRedactor;

/**
 * An answer the bridge failed to convert, as its raw answer shows it: cut
 * short (`$stopReason` named as `LLMResponse` names it), refused as too large
 * with an HTTP 413, or refused with another HTTP client error, which books
 * nothing and is classified by the bridge's message alone.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class UnconvertedAnswerException extends RuntimeException
{
    public function __construct(
        string $message,
        Throwable $previous,
        public readonly ?string $stopReason = null,
        public readonly bool $refusedAsTooLarge = false,
        public readonly bool $refusedWithClientError = false,
    ) {
        parent::__construct($message, previous: $previous);
    }

    public static function cutShort(Throwable $throwable, string $stopReason): self
    {
        return new self(ProviderMessageRedactor::redact($throwable->getMessage()), $throwable, $stopReason);
    }

    public static function refusedAsTooLarge(Throwable $throwable): self
    {
        return new self(\sprintf('The provider refused the request as too large (HTTP 413): %s', ProviderMessageRedactor::redact($throwable->getMessage())), $throwable, refusedAsTooLarge: true);
    }

    public static function refusedWithStatus(Throwable $throwable, int $status): self
    {
        return new self(\sprintf('The provider refused the request (HTTP %d): %s', $status, ProviderMessageRedactor::redact($throwable->getMessage())), $throwable, refusedWithClientError: true);
    }
}
