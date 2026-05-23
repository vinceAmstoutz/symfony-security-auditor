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

/** @internal not part of the BC promise — see docs/versioning.md */
final class TransientLLMFailureException extends RuntimeException
{
    public static function afterExhaustedAttempts(int $attempts, Throwable $throwable): self
    {
        return new self(
            \sprintf('LLM call failed after %d transient retries: %s', $attempts, $throwable->getMessage()),
            previous: $throwable,
        );
    }
}
