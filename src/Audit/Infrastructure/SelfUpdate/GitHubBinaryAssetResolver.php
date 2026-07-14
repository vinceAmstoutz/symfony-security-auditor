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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\Exception\UnsupportedSelfUpdatePlatformException;

/**
 * Resolves the release asset for the running platform, mirroring the OS/arch
 * detection in `install.sh` so the binary self-updates to the same asset the
 * installer would have fetched.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class GitHubBinaryAssetResolver
{
    private const string REPOSITORY = 'vinceAmstoutz/symfony-security-auditor';

    private const string BINARY_NAME = 'symfony-security-auditor';

    private const string DOWNLOAD_URL_TEMPLATE = 'https://github.com/%s/releases/download/%s/%s';

    public function __construct(
        private string $osFamily,
        private string $machine,
    ) {}

    /**
     * @throws UnsupportedSelfUpdatePlatformException
     */
    public function resolve(string $version): GitHubBinaryAsset
    {
        $assetName = \sprintf('%s-%s-%s', self::BINARY_NAME, $this->osSlug(), $this->architectureSlug());
        $downloadUrl = \sprintf(self::DOWNLOAD_URL_TEMPLATE, self::REPOSITORY, $version, $assetName);

        return new GitHubBinaryAsset($assetName, $downloadUrl, \sprintf('%s.sha256', $downloadUrl));
    }

    /**
     * @throws UnsupportedSelfUpdatePlatformException
     */
    private function osSlug(): string
    {
        return match ($this->osFamily) {
            'Linux' => 'linux',
            'Darwin' => 'macos',
            default => throw UnsupportedSelfUpdatePlatformException::forPlatform($this->osFamily, $this->machine),
        };
    }

    /**
     * @throws UnsupportedSelfUpdatePlatformException
     */
    private function architectureSlug(): string
    {
        return match ($this->machine) {
            'x86_64', 'amd64' => 'x86_64',
            'aarch64', 'arm64' => 'Darwin' === $this->osFamily ? 'arm64' : 'aarch64',
            default => throw UnsupportedSelfUpdatePlatformException::forPlatform($this->osFamily, $this->machine),
        };
    }
}
