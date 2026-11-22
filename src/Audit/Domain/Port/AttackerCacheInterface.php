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
 * Per-chunk cache of the attacker's raw findings, keyed by the chunk's sorted
 * (relative path, content hash) pairs. A hit skips the LLM call. Payloads go
 * to VulnerabilityFactory::fromList(), which drops malformed entries, so an
 * implementation validates nothing beyond JSON.
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
