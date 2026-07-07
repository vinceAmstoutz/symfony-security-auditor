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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\Exception\InvalidCacheConfigurationException;

use function Symfony\Component\String\u;

/**
 * Filesystem-backed reviewer-verdict cache. The key is the SHA-256 of the
 * finding's stable content (its `toArray()` minus the non-deterministic `id`)
 * plus the reviewed code context, folded behind an optional key salt
 * (reviewer model + cache version) so a model or contract change invalidates
 * every stored verdict.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FilesystemReviewerCache implements ReviewerCacheInterface
{
    /**
     * Folded into the key salt so a reviewer-prompt or verdict-contract change
     * invalidates every previously cached verdict. Bump when the reviewer prompt
     * or the applied-review semantics change in a way that should re-run review.
     */
    public const int CACHE_VERSION = 1;

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function __construct(
        private string $cacheDir,
        private Filesystem $filesystem,
        private LoggerInterface $logger,
        private string $keySalt = '',
    ) {
        if (u($cacheDir)->trim()->isEmpty()) {
            throw InvalidCacheConfigurationException::forEmptyCacheDir();
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
            $encoded = json_encode($review, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
            $this->filesystem->mkdir(\dirname($path));
            $this->filesystem->dumpFile($path, $encoded);
            $this->logger->debug('Reviewer cache stored', ['path' => $path]);
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to write reviewer cache entry', [
                'path' => $path,
                'error' => $throwable->getMessage(),
            ]);
        }
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

        $signature = \sprintf("%s\0%s", json_encode($finding, \JSON_THROW_ON_ERROR), $codeContext);
        if ('' !== $this->keySalt) {
            $signature = \sprintf("%s\0%s", $this->keySalt, $signature);
        }

        return hash('sha256', $signature);
    }
}
