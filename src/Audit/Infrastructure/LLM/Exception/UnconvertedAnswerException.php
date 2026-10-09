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
 * An answer the provider delivered but its bridge failed to convert, as its
 * raw answer shows it: cut short, which `$stopReason` names the way
 * `LLMResponse` does (`length`, `content-filter`), keeping the bridge's
 * message; a request refused as too large with an HTTP 413, whose body the
 * bridge could not make sense of; or a request refused with any other HTTP
 * client error, whose body the bridge read as an empty answer.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class UnconvertedAnswerException extends RuntimeException
{
    public function __construct(
        string $message,
        Throwable $previous,
        public readonly ?string $stopReason = null,
        public readonly bool $refusedAsTooLarge = false,
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
        return new self(\sprintf('The provider refused the request (HTTP %d): %s', $status, ProviderMessageRedactor::redact($throwable->getMessage())), $throwable);
    }
}
