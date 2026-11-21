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
 * A stream that ended without saying why the model stopped: cut on the way,
 * though its bridge did not report it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class UnfinishedStreamException extends IncompleteStreamException
{
    public static function withoutFinishReason(): self
    {
        return new self('The stream ended before the model said why it stopped.');
    }
}
