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

final class InvalidGroundTruthManifestException extends RuntimeException
{
    public static function forUnreadablePath(string $path): self
    {
        return new self(\sprintf('Ground-truth manifest "%s" does not exist or is not readable.', $path));
    }

    public static function fromJsonException(string $path, Throwable $throwable): self
    {
        return new self(\sprintf('Ground-truth manifest "%s" is not valid JSON: %s', $path, $throwable->getMessage()), previous: $throwable);
    }

    public static function forMissingFindingsArray(string $path): self
    {
        return new self(\sprintf('Ground-truth manifest "%s" must be a JSON object with a "findings" array.', $path));
    }

    public static function forInvalidFinding(string $path, int $index): self
    {
        return new self(\sprintf('Ground-truth manifest "%s" has an invalid finding at index %d: "file" and "type" must both be non-empty strings.', $path, $index));
    }
}
