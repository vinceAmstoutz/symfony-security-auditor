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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;

/**
 * Thrown when a single request's estimated input tokens exceed the entire
 * rate-limit window — the request can never fit, no amount of waiting helps.
 * Extends `LLMRequestTooLargeException` so the chunk analyzers split the
 * chunk the same way they do for a prompt the model itself refuses.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class RateLimitRequestTooLargeException extends LLMRequestTooLargeException
{
    public static function from(int $estimatedInputTokens, int $windowCapacityTokens): self
    {
        return new self(\sprintf(
            'estimated input tokens (%d) exceed window capacity (%d)',
            $estimatedInputTokens,
            $windowCapacityTokens,
        ));
    }
}
