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

/**
 * A stream that ended without content, worded as the bridges word an empty
 * buffered answer.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class EmptyStreamedAnswerException extends RuntimeException
{
    public static function create(): self
    {
        return new self('Response does not contain any content.');
    }
}
