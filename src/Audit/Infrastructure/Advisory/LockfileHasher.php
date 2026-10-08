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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;

use function Symfony\Component\String\u;

/**
 * SHA-256 of the audited project's `composer.lock`, or `null` when there is
 * no lockfile to key an advisory snapshot on. The project is untrusted, so a
 * lockfile that is a symlink (`composer.lock -> /dev/zero`) or larger than
 * `MAX_LOCKFILE_BYTES` is refused before it is read.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class LockfileHasher
{
    public const int MAX_LOCKFILE_BYTES = 8_388_608;

    public function __construct(
        private Filesystem $filesystem,
        private LoggerInterface $logger,
    ) {}

    public function hash(string $projectPath): ?string
    {
        $lockfilePath = \sprintf('%s/composer.lock', u($projectPath)->trimEnd('/')->toString());

        if (!$this->filesystem->exists($lockfilePath) || $this->isRefused($lockfilePath)) {
            return null;
        }

        try {
            $contents = $this->filesystem->readFile($lockfilePath);
        } catch (IOException $ioException) {
            $this->logger->warning('composer.lock present but unreadable; skipping advisory cache', [
                'path' => $lockfilePath,
                'error' => $ioException->getMessage(),
            ]);

            return null;
        }

        return hash('sha256', $contents);
    }

    private function isRefused(string $lockfilePath): bool
    {
        if (is_link($lockfilePath)) {
            $this->logger->warning('composer.lock is a symlink; skipping advisory cache', ['path' => $lockfilePath]);

            return true;
        }

        $bytes = filesize($lockfilePath);
        \assert(false !== $bytes, 'filesize() must succeed for a path exists() already confirmed present');

        if ($bytes > self::MAX_LOCKFILE_BYTES) {
            $this->logger->warning('composer.lock is too large; skipping advisory cache', [
                'path' => $lockfilePath,
                'bytes' => $bytes,
                'max_bytes' => self::MAX_LOCKFILE_BYTES,
            ]);

            return true;
        }

        return false;
    }
}
