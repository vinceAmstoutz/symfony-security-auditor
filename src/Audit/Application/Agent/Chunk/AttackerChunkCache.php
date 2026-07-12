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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk;

use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ContextAwareAttackerCacheInterface;

/**
 * Adapts {@see AttackerCacheInterface} for chunk analysis: transparently uses
 * the context-aware key when the wired cache supports it (so iterations 2+ are
 * cacheable), falling back to the context-free key otherwise, and turns a cache
 * hit into a hydrated result with coverage + logging. A store failure is
 * caught and logged rather than left to propagate — the caller already has
 * the chunk's findings in hand by the time it stores them, so losing the
 * cache write must never cost the caller the findings themselves.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AttackerChunkCache
{
    public function __construct(
        private AttackerCacheInterface $attackerCache,
        private VulnerabilityFactory $vulnerabilityFactory,
        private LoggerInterface $logger,
    ) {}

    public function isContextAware(): bool
    {
        return $this->attackerCache instanceof ContextAwareAttackerCacheInterface;
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @return array<int, array<string, mixed>>|null
     */
    public function get(array $chunk, string $contextKey): ?array
    {
        return $this->attackerCache instanceof ContextAwareAttackerCacheInterface
            ? $this->attackerCache->getForContext($chunk, $contextKey)
            : $this->attackerCache->get($chunk);
    }

    /**
     * @param list<ProjectFile>          $chunk
     * @param list<array<string, mixed>> $rawVulnerabilities
     */
    public function store(array $chunk, string $contextKey, array $rawVulnerabilities): void
    {
        try {
            if ($this->attackerCache instanceof ContextAwareAttackerCacheInterface) {
                $this->attackerCache->storeForContext($chunk, $contextKey, $rawVulnerabilities);

                return;
            }

            $this->attackerCache->store($chunk, $rawVulnerabilities);
        } catch (Throwable $throwable) {
            $this->logger->warning('Failed to write attacker cache entry', [
                'error' => $throwable->getMessage(),
            ]);
        }
    }

    /**
     * @param list<ProjectFile>                $chunk
     * @param array<int, array<string, mixed>> $cached
     */
    public function served(array $chunk, array $cached, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $this->logger->info('Attacker chunk served from cache', ['files' => \count($chunk)]);
        ChunkCoverageRecorder::record($chunk, 'cached', $coverageRecorder);

        return $this->vulnerabilityFactory->fromList(array_values($cached));
    }
}
