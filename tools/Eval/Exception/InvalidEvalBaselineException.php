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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\Exception;

use RuntimeException;
use Throwable;

final class InvalidEvalBaselineException extends RuntimeException
{
    public static function forUnreadablePath(string $path): self
    {
        return new self(\sprintf('Eval baseline "%s" does not exist or is not readable. Record one with `bin/castor eval --write-baseline`.', $path));
    }

    public static function fromJsonException(string $path, Throwable $throwable): self
    {
        return new self(\sprintf('Eval baseline "%s" is not valid JSON: %s', $path, $throwable->getMessage()), previous: $throwable);
    }

    public static function forMissingScoresObject(string $path): self
    {
        return new self(\sprintf('Eval baseline "%s" must be a JSON object with a "scores" object keyed by vulnerability class.', $path));
    }

    public static function forInvalidScore(string $path, string $type): self
    {
        return new self(\sprintf('Eval baseline "%s" has an invalid score for "%s": "precision" and "recall" must both be numbers between 0 and 1.', $path, $type));
    }
}
