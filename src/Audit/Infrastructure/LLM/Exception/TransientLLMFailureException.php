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

use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;

/**
 * Thrown when every retry attempt for a transient LLM error is exhausted
 * (e.g. repeated 429 rate-limit responses or 5xx failures). Extends
 * `LLMProviderException` so agents can catch it at the Domain boundary and
 * abort the audit rather than silently producing a false-negative SAFE result.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class TransientLLMFailureException extends LLMProviderException
{
    public static function afterExhaustedAttempts(int $attempts, Throwable $throwable): self
    {
        return new self(
            \sprintf('LLM call failed after %d attempts: %s', $attempts, $throwable->getMessage()),
            previous: $throwable,
        );
    }
}
