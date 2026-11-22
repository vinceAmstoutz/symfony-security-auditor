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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * A cache-miss chunk awaiting its batch call, with its context and the
 * collection session its `record_vulnerability` calls land in.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class PendingChunk
{
    /**
     * @param list<ProjectFile> $chunk
     */
    public function __construct(
        public array $chunk,
        public ChunkContext $chunkContext,
        public StructuredVulnerabilityCollectionSession $session,
    ) {}
}
