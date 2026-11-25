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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\ProviderMessageRedactor;

/** @internal not part of the BC promise, see docs/versioning.md */
final class NonTransientLLMFailureException extends LLMProviderException
{
    public static function from(Throwable $throwable): self
    {
        return new self(
            \sprintf('LLM call failed with non-transient error: %s', ProviderMessageRedactor::redact($throwable->getMessage())),
            previous: $throwable,
        );
    }

    public static function forUnknownModel(string $model, Throwable $throwable): self
    {
        return new self(
            \sprintf('The provider does not know the model "%s": %s. Set model: in the standalone config.yaml or run init --model=<model id>, or set symfony_security_auditor.model in a Symfony application.', $model, ProviderMessageRedactor::redact($throwable->getMessage())),
            previous: $throwable,
        );
    }
}
