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
 * A request the provider failed with an HTTP status that clears on its own —
 * a request timeout, a request that came too early, a rate limit or a server
 * error — read from the raw answer of a conversion that failed, whatever the
 * bridge made of the body that came with it. Nothing was served, so it is
 * retried with the usual back-off and booked as nothing. It keeps the
 * bridge's message, and the failure as it reads without the status
 * (`$statusFreeFailure`), which decides once the retries are spent.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class TransientHttpStatusException extends RuntimeException
{
    private function __construct(
        string $message,
        public readonly Throwable $statusFreeFailure,
        public readonly int $status,
    ) {
        parent::__construct($message, previous: $statusFreeFailure);
    }

    public static function from(Throwable $throwable, int $status): self
    {
        return new self(ProviderMessageRedactor::redact($throwable->getMessage()), $throwable, $status);
    }
}
