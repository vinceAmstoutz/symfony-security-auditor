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

use Symfony\AI\Platform\Exception\IncompleteStreamException;

/**
 * A stream that ended without reporting its usage, so its bill is unknown:
 * the call is sent again, and the platform is no longer streamed.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class UnmeteredStreamException extends IncompleteStreamException
{
    public static function withoutUsage(): self
    {
        return new self('The stream ended without reporting the tokens it used.');
    }
}
