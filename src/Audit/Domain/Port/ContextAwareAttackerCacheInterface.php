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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Opt-in extension of {@see AttackerCacheInterface} for caches that can key an
 * entry by the chunk PLUS the cross-iteration prompt context (prior validated
 * findings, reviewer-rejected findings) injected ahead of it. Consumers check
 * `instanceof ContextAwareAttackerCacheInterface` and fall back to skipping
 * the cache for context-carrying chunks when it is not implemented, so adding
 * this capability never breaks an existing cache.
 *
 * An empty `$contextKey` MUST address the same entry as the context-free
 * {@see AttackerCacheInterface::get()} / `store()` pair, so entries written
 * before this capability existed stay readable.
 */
interface ContextAwareAttackerCacheInterface extends AttackerCacheInterface
{
    /**
     * @param list<ProjectFile> $chunk
     *
     * @return array<int, array<string, mixed>>|null raw vulnerability dicts, or null on miss
     */
    public function getForContext(array $chunk, string $contextKey): ?array;

    /**
     * @param list<ProjectFile>          $chunk
     * @param list<array<string, mixed>> $rawVulnerabilities
     */
    public function storeForContext(array $chunk, string $contextKey, array $rawVulnerabilities): void;
}
