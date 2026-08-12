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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class ProjectConfigScanOverrideException extends RuntimeException
{
    /**
     * @param list<string> $keys
     */
    public static function forKeys(string $projectConfigFile, array $keys): self
    {
        return new self(\sprintf(
            'The project config "%s" declares %s, which can read or reference files outside the audited project — a repository you audit must not be able to point the scanner at paths of its choosing. Configure it in your user config instead.',
            $projectConfigFile,
            implode(' and ', array_map(static fn (string $key): string => \sprintf('"%s"', $key), $keys)),
        ));
    }
}
