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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge;

use Composer\InstalledVersions;

/**
 * The `symfony/ai-platform` release this binary was built with, read from its
 * own vendor tree, never from the bridge tree. Null when that package is not
 * installed as a tagged release.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class BundledAiPlatformVersion
{
    private const string PACKAGE = 'symfony/ai-platform';

    private const string ROOT_PACKAGE = 'vinceamstoutz/symfony-security-auditor';

    private const string RELEASE_PATTERN = '/^v?\d+\.\d+\.\d+$/';

    /**
     * @param list<array<string, mixed>>|null $installedData Composer's raw installed data per vendor tree, defaults to what the autoloaders registered
     */
    public static function detect(?array $installedData = null): ?string
    {
        foreach ($installedData ?? InstalledVersions::getAllRawData() as $installed) {
            $root = $installed['root'] ?? null;
            if (\is_array($root) && self::ROOT_PACKAGE === ($root['name'] ?? null)) {
                return self::releaseVersionIn($installed);
            }
        }

        return null;
    }

    /**
     * Returns the `symfony/ai-platform` version installed-package data records,
     * a branch version included.
     *
     * @param array<array-key, mixed> $installed
     */
    public static function recordedIn(array $installed): ?string
    {
        $versions = $installed['versions'] ?? null;
        $package = \is_array($versions) ? ($versions[self::PACKAGE] ?? null) : null;
        $version = \is_array($package) ? ($package['pretty_version'] ?? null) : null;

        return \is_string($version) ? $version : null;
    }

    /**
     * @param array<string, mixed> $installed
     */
    private static function releaseVersionIn(array $installed): ?string
    {
        $version = self::recordedIn($installed);

        return null !== $version && 1 === preg_match(self::RELEASE_PATTERN, $version) ? $version : null;
    }
}
