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

/** @internal not part of the BC promise — see docs/versioning.md */
final class NonTransientLLMFailureException extends LLMProviderException
{
    public static function from(Throwable $throwable): self
    {
        return new self(
            \sprintf('LLM call failed with non-transient error: %s', $throwable->getMessage()),
            previous: $throwable,
        );
    }
}
