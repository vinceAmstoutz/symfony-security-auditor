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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception;

use RuntimeException;
use Throwable;

final class MalformedAdvisoryPayloadException extends RuntimeException
{
    public static function forInvalidJson(Throwable $throwable): self
    {
        return new self(
            \sprintf('composer audit emitted invalid JSON: %s', $throwable->getMessage()),
            previous: $throwable,
        );
    }

    public static function forMissingAdvisoriesKey(): self
    {
        return new self('composer audit JSON is missing the expected "advisories" key');
    }
}
