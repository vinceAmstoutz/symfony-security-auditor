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
 * Optional extension of {@see AttackerCacheInterface}, checked with
 * `instanceof`: keys an entry by the chunk and by `$contextKey`, which covers
 * the prompt context injected ahead of it (the cross-iteration preambles and
 * the risk-marker preamble). Without it, a chunk carrying context skips the
 * cache.
 *
 * An empty `$contextKey` MUST address the same entry as the context-free
 * {@see AttackerCacheInterface::get()} / `store()` pair.
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
