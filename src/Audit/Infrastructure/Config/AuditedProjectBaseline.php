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
 * Refuses a baseline named by the audited project's config unless its real
 * path is a regular file inside the project, small enough to decode. One
 * that does not exist yet passes.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
        \assert(false !== $realProject, 'realpath() must succeed for the folder of a config file just read');

        if (false === $realBaseline || !is_file($realBaseline) || !Path::isBasePath($realProject, $realBaseline)) {
            throw MalformedProjectConfigException::forBaselineOutsideProject($projectConfigFile, $baseline);
        }

        if (filesize($realBaseline) > self::MAX_BYTES) {
            throw MalformedProjectConfigException::forOversizedBaseline($projectConfigFile, $baseline, self::MAX_BYTES);
        }
    }
}
