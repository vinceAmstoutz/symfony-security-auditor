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
 * The model answered with nothing usable. `$stopReason` names the outcome the
 * way `LLMResponse` does when a provider reports it as a response instead —
 * `empty_content`, `length` or `content-filter` — so the caller can hand back
 * the same degraded response either way.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class EmptyLLMResponseException extends RuntimeException
{
    public function __construct(string $message, Throwable $previous, public readonly string $stopReason)
    {
        parent::__construct($message, previous: $previous);
    }

    public static function from(Throwable $throwable, string $stopReason = 'empty_content'): self
    {
        return new self(
            \sprintf('LLM returned a response with no content: %s', ProviderMessageRedactor::redact($throwable->getMessage())),
            $throwable,
            $stopReason,
        );
    }
}
