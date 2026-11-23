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

/**
 * Thrown once every retry of a transient failure is spent. Agents catch it as
 * `LLMProviderException` and abort the audit rather than report a false SAFE.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class TransientLLMFailureException extends LLMProviderException
{
    public function __construct(
        string $message,
        private readonly Throwable $throwable,
        public readonly int $attempts,
    ) {
        parent::__construct($message, previous: $throwable);
    }

    public static function afterExhaustedAttempts(int $attempts, Throwable $throwable): self
    {
        return new self(\sprintf('LLM call failed after %d attempts: %s', $attempts, ProviderMessageRedactor::redact($throwable->getMessage())), $throwable, $attempts);
    }

    /**
     * Returns the same failure, counting the attempt that failed before the
     * retries began.
     */
    public function afterOneMoreAttempt(): self
    {
        return self::afterExhaustedAttempts($this->attempts + 1, $this->throwable);
    }
}
