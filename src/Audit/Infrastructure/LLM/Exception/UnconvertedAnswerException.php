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

/**
 * An answer the provider delivered but its bridge failed to convert, as its
 * raw answer shows it: cut short, which `$stopReason` names the way
 * `LLMResponse` does (`length`, `content-filter`). It keeps the bridge's
 * message.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class UnconvertedAnswerException extends RuntimeException
{
    public function __construct(Throwable $previous, public readonly string $stopReason)
    {
        parent::__construct($previous->getMessage(), previous: $previous);
    }

    public static function cutShort(Throwable $throwable, string $stopReason): self
    {
        return new self($throwable, $stopReason);
    }
}
