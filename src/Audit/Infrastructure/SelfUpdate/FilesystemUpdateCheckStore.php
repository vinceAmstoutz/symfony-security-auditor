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

use DateTimeImmutable;
use JsonException;
use Override;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\UnresolvableConfigPathException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;

/**
 * Persists the last update check under the XDG cache directory as a small JSON
 * document. Every I/O or decoding failure degrades to a cache miss (`read()`
 * returns `null`) or a no-op (`write()`), logged but never thrown, so the update
 * notice is only ever a best-effort convenience and can never abort a command.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FilesystemUpdateCheckStore implements UpdateCheckStoreInterface
{
    private const string CACHE_FILENAME = 'update-check.json';

    private const string CHECKED_AT_KEY = 'checked_at';

    private const string LATEST_VERSION_KEY = 'latest_version';

    public function __construct(
        private XdgConfigPathResolver $xdgConfigPathResolver,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
    ) {}

    #[Override]
    public function read(): ?UpdateCheckState
    {
        $path = $this->cacheFilePath();
        if (null === $path || !$this->filesystem->exists($path)) {
            return null;
        }

        try {
            $raw = $this->filesystem->readFile($path);
        } catch (IOException $ioException) {
            $this->logger->warning('Update-check cache is unreadable', ['error' => $ioException->getMessage()]);

            return null;
        }

        return $this->parse($raw);
    }

    #[Override]
    public function write(UpdateCheckState $updateCheckState): void
    {
        $path = $this->cacheFilePath();
        if (null === $path) {
            return;
        }

        $payload = json_encode([
            self::CHECKED_AT_KEY => $updateCheckState->checkedAt->getTimestamp(),
            self::LATEST_VERSION_KEY => $updateCheckState->latestVersion,
        ]);
        \assert(false !== $payload, 'A timestamp-and-version array is always JSON-encodable');

        try {
            $this->filesystem->dumpFile($path, $payload);
        } catch (IOException $ioException) {
            $this->logger->warning('Failed to write the update-check cache', ['error' => $ioException->getMessage()]);
        }
    }

    private function parse(string $raw): ?UpdateCheckState
    {
        try {
            $decoded = json_decode($raw, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (!\is_array($decoded)) {
            return null;
        }

        $checkedAt = $decoded[self::CHECKED_AT_KEY] ?? null;
        $latestVersion = $decoded[self::LATEST_VERSION_KEY] ?? null;

        if (!\is_int($checkedAt) || !\is_string($latestVersion) || '' === $latestVersion) {
            return null;
        }

        return new UpdateCheckState(new DateTimeImmutable(\sprintf('@%d', $checkedAt)), $latestVersion);
    }

    private function cacheFilePath(): ?string
    {
        try {
            return \sprintf('%s/%s', $this->xdgConfigPathResolver->cacheDir(), self::CACHE_FILENAME);
        } catch (UnresolvableConfigPathException) {
            return null;
        }
    }
}
