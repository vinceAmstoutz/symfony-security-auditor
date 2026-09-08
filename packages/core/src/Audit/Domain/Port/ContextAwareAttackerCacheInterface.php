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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Opt-in extension of {@see AttackerCacheInterface} for caches keyed by the
 * chunk plus the prompt context injected ahead of it — the cross-iteration and
 * risk-marker preambles, which change the prompt on an unchanged content hash.
 * Consumers check `instanceof` and otherwise skip the cache for
 * context-carrying chunks, so adding this never breaks an existing cache.
 *
 * An empty `$contextKey` MUST address the same entry as the context-free
 * {@see AttackerCacheInterface::get()} / `store()` pair, so entries written
 * before this capability stay readable.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
