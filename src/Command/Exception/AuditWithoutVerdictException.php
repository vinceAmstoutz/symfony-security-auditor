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

/** @internal not part of the BC promise — see docs/versioning.md */
final class AuditWithoutVerdictException extends RuntimeException
{
    public static function forNoFileDiscovered(string $projectPath): self
    {
        return new self(\sprintf('The audit of "%s" has no verdict: the scan found no file to audit. Check the path and the scan.included_paths configuration.', $projectPath));
    }

    public static function forNoFileAnalyzed(string $projectPath, int $fileCount): self
    {
        return new self(\sprintf('The audit of "%s" has no verdict: none of its %d file(s) could be analyzed, because every LLM call failed. The server log names the cause.', $projectPath, $fileCount));
    }
}
