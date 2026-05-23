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

final class NonTransientLLMFailureException extends RuntimeException
{
    public static function from(Throwable $throwable): self
    {
        return new self(
            \sprintf('LLM call failed with non-transient error: %s', $throwable->getMessage()),
            previous: $throwable,
        );
    }
}
