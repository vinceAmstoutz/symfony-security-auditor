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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Per-chunk vulnerability cache. The key is derived from the sorted set of
 * (relativePath, contentHash) tuples in the chunk. A cache hit short-circuits
 * the LLM call entirely.
 *
 * Stored payloads are raw vulnerability dicts ready for VulnerabilityFactory::fromList().
 * The factory tolerates partially malformed entries, so cache implementations are
 * not required to validate structure beyond JSON parsing.
 */
interface AttackerCacheInterface
{
    /**
     * @param list<ProjectFile> $chunk
     *
     * @return array<int, array<string, mixed>>|null raw vulnerability dicts, or null on miss
     */
    public function get(array $chunk): ?array;

    /**
     * @param list<ProjectFile>          $chunk
     * @param list<array<string, mixed>> $rawVulnerabilities
     */
    public function store(array $chunk, array $rawVulnerabilities): void;
}
