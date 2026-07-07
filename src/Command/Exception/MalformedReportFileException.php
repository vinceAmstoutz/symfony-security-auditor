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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\Exception;

use RuntimeException;
use Throwable;

/** @internal not part of the BC promise — see docs/versioning.md */
final class MalformedReportFileException extends RuntimeException
{
    public static function fromJsonException(string $path, Throwable $throwable): self
    {
        return new self(\sprintf('Report file "%s" is not valid JSON: %s', $path, $throwable->getMessage()), previous: $throwable);
    }

    public static function missingVulnerabilitiesArray(string $path): self
    {
        return new self(\sprintf('Report file "%s" must be a JSON object with a "vulnerabilities" array.', $path));
    }

    public static function invalidVulnerabilityEntry(string $path, int $index): self
    {
        return new self(\sprintf('Report file "%s" has an invalid vulnerability entry at index %d: "type", "file", "title", and "severity" must all be strings.', $path, $index));
    }

    public static function vulnerabilityEntryNotAnObject(string $path, int $index): self
    {
        return new self(\sprintf('Report file "%s" has a vulnerability entry at index %d that is not a JSON object.', $path, $index));
    }
}
