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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache;

use JsonException;
use Override;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullReviewerFeedbackProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\Exception\InvalidCacheConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\Exception\UnsafeCacheWriteException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\PrivateFileWriter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\SymlinkGuard;

use function Symfony\Component\String\u;

/**
 * Reviewer verdicts keyed by the SHA-256 of the finding without its `id` and
 * `detected_at`, the reviewed code context, the optional key salt (reviewer
 * model and cache version) and the reviewer feedback.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class FilesystemReviewerCache implements ReviewerCacheInterface
{
    /**
     * Bump to invalidate every cached verdict when the reviewer prompt or the
     * verdict contract changes.
     */
    public const int CACHE_VERSION = 1;

    /**
     * Bump when the prompt presents feedback differently: it invalidates only
     * the verdicts cached under feedback.
     */
    private const string FEEDBACK_KEY_VERSION = 'v2';

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function __construct(
        private string $cacheDir,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
        private string $keySalt = '',
        private ReviewerFeedbackProviderInterface $reviewerFeedbackProvider = new NullReviewerFeedbackProvider(),
    ) {
        if (u($cacheDir)->trim()->isEmpty()) {
            throw InvalidCacheConfigurationException::forEmptyCacheDir('Reviewer');
        }
    }

    #[Override]
    public function get(Vulnerability $vulnerability, string $codeContext): ?array
    {
        $path = null;

        try {
            $path = $this->pathFor($vulnerability, $codeContext);

            if (!$this->filesystem->exists($path)) {
                return null;
            }

            if ($this->isSymlinkedPath($path)) {
                $this->logger->warning('Reviewer cache entry path was a symlink, ignoring', ['path' => $path]);

                return null;
            }

            $decoded = json_decode($this->filesystem->readFile($path), true, flags: \JSON_THROW_ON_ERROR);
            if (!\is_array($decoded)) {
                return null;
            }

            $this->logger->debug('Reviewer cache hit', ['path' => $path]);

            return $this->coerceToReview($decoded);
        } catch (IOException|JsonException $exception) {
            $this->logger->warning('Reviewer cache entry was unreadable, ignoring', [
                'path' => $path,
                'error' => $exception->getMessage(),
            ]);

            return null;
        }
    }

    #[Override]
    public function store(Vulnerability $vulnerability, string $codeContext, array $review): void
    {
        $path = null;

        try {
            $path = $this->pathFor($vulnerability, $codeContext);
            $this->assertSafeToWrite($path);
            $encoded = json_encode($review, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
            PrivateFileWriter::write($this->filesystem, $path, $encoded);
            $this->logger->debug('Reviewer cache stored', ['path' => $path]);
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to write reviewer cache entry', [
                'path' => $path,
                'error' => $throwable->getMessage(),
            ]);
        }
    }

    /**
     * Refuses a path through a symlink: the path derives from the finding,
     * which the audited project influences, so a planted link would redirect
     * the write.
     *
     * @throws UnsafeCacheWriteException
     */
    private function assertSafeToWrite(string $path): void
    {
        if ($this->isSymlinkedPath($path)) {
            throw UnsafeCacheWriteException::forSymlinkedPath($path);
        }
    }

    /**
     * Trusts the configured `cache.dir` (this cache's parent) and every
     * directory above it, on read and on write.
     */
    private function isSymlinkedPath(string $path): bool
    {
        return SymlinkGuard::isThroughSymlink($path, \dirname($this->cacheDir));
    }

    /**
     * @param array<int|string, mixed> $decoded
     *
     * @return array<string, mixed>
     */
    private function coerceToReview(array $decoded): array
    {
        $review = [];
        foreach ($decoded as $key => $value) {
            $review[(string) $key] = $value;
        }

        return $review;
    }

    private function pathFor(Vulnerability $vulnerability, string $codeContext): string
    {
        $key = $this->keyFor($vulnerability, $codeContext);

        return \sprintf('%s/%s/%s.json', u($this->cacheDir)->trimEnd('/')->toString(), u($key)->slice(0, 2)->toString(), $key);
    }

    private function keyFor(Vulnerability $vulnerability, string $codeContext): string
    {
        $finding = $vulnerability->toArray();
        unset($finding['id']);
        unset($finding['detected_at']);

        $signature = \sprintf("%s\0%s", json_encode($finding, \JSON_THROW_ON_ERROR), $codeContext);
        if ('' !== $this->keySalt) {
            $signature = \sprintf("%s\0%s", $this->keySalt, $signature);
        }

        $feedbackDigest = $this->reviewerFeedbackProvider->feedback()->digest();
        if ('' !== $feedbackDigest) {
            $signature = \sprintf("%s\0feedback-%s-%s", $signature, self::FEEDBACK_KEY_VERSION, $feedbackDigest);
        }

        return hash('sha256', $signature);
    }
}
