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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\Exception\StaleBridgeTreeException;

/**
 * The composer project under the data directory that `init` installs the
 * provider bridges into. The binary registers its autoloader ahead of its own,
 * so the `symfony/ai-platform` it holds replaces the bundled one: a tree built
 * by an older release is read before it is loaded, from the installed-package
 * data Composer writes beside the autoloader, and refused when it holds
 * another release.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class BridgeTree
{
    private const string AUTOLOAD_FILE = '%s/vendor/autoload.php';

    private const string INSTALLED_PACKAGES_FILE = '%s/vendor/composer/installed.php';

    /**
     * @param ?string $bundledAiPlatformVersion the `symfony/ai-platform` release this binary bundles ({@see BundledAiPlatformVersion}); no tree conflicts with an unknown one
     */
    public function __construct(
        public string $directory,
        private ?string $bundledAiPlatformVersion,
    ) {}

    public function autoloadFile(): string
    {
        return \sprintf(self::AUTOLOAD_FILE, $this->directory);
    }

    public function isInstalled(): bool
    {
        return is_file($this->autoloadFile());
    }

    /**
     * @param ?string $provider the configured provider the advice names, or null when none is known
     *
     * @throws StaleBridgeTreeException
     */
    public function assertLoadable(?string $provider): void
    {
        $treeVersion = $this->aiPlatformVersion();

        if (null === $this->bundledAiPlatformVersion || null === $treeVersion || $treeVersion === $this->bundledAiPlatformVersion) {
            return;
        }

        throw StaleBridgeTreeException::forTree($this->directory, $treeVersion, $this->bundledAiPlatformVersion, $provider);
    }

    private function aiPlatformVersion(): ?string
    {
        $installedPackagesFile = \sprintf(self::INSTALLED_PACKAGES_FILE, $this->directory);
        if (!is_file($installedPackagesFile)) {
            return null;
        }

        $installed = require $installedPackagesFile;

        return \is_array($installed) ? BundledAiPlatformVersion::recordedIn($installed) : null;
    }
}
