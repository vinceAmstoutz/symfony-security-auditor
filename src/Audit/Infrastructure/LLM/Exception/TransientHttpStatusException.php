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
 * A request failed with an HTTP status that clears on its own (408, 425, 429
 * or 5xx), whatever the bridge made of its body. It is retried and books
 * nothing; once the retries are spent, `$statusFreeFailure` decides.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
