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

/**
 * Reads a relative path a project config names from the folder that holds
 * the config file, not from the working directory.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ProjectConfigPathAnchor
{
    /**
     * @param array<array-key, mixed> $projectConfig
     *
     * @return array<array-key, mixed>
     */
    public static function anchored(array $projectConfig, string $projectConfigFile): array
    {
        $audit = $projectConfig['audit'] ?? null;
        $baseline = \is_array($audit) ? ($audit['baseline'] ?? null) : null;

        if (!\is_array($audit) || !\is_string($baseline) || '' === $baseline || Path::isAbsolute($baseline)) {
            return $projectConfig;
        }

        $audit['baseline'] = Path::makeAbsolute($baseline, \dirname($projectConfigFile));
        $projectConfig['audit'] = $audit;

        return $projectConfig;
    }
}
