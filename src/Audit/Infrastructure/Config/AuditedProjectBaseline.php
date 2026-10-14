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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\MalformedProjectConfigException;

/**
 * The baseline the audited project's own config names is read whole and
 * decoded, and the repository chose it: so it must be a regular file inside
 * the project, by its real path (a link to `/dev/zero` or to a file of the
 * user's is refused, as for `composer.lock`), and small enough to decode
 * within the binary's memory. One that does not exist yet is never read.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AuditedProjectBaseline
{
    private const int MAX_BYTES = 1_048_576;

    /**
     * @param array<array-key, mixed> $projectConfig the audited project's config, its baseline anchored to the project
     *
     * @throws MalformedProjectConfigException
     */
    public static function assertReadable(array $projectConfig, string $projectConfigFile): void
    {
        $audit = $projectConfig['audit'] ?? null;
        $baseline = \is_array($audit) ? ($audit['baseline'] ?? null) : null;
        if (!\is_string($baseline) || !file_exists($baseline)) {
            return;
        }

        $realBaseline = realpath($baseline);
        $realProject = realpath(\dirname($projectConfigFile));
        \assert(false !== $realBaseline && false !== $realProject, 'realpath() must succeed for paths file_exists() found');

        if (!is_file($realBaseline) || !Path::isBasePath($realProject, $realBaseline)) {
            throw MalformedProjectConfigException::forBaselineOutsideProject($projectConfigFile, $baseline);
        }

        if (filesize($realBaseline) > self::MAX_BYTES) {
            throw MalformedProjectConfigException::forOversizedBaseline($projectConfigFile, $baseline, self::MAX_BYTES);
        }
    }
}
