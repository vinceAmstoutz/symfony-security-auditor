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
 * One cache-miss chunk awaiting a dispatched batch call: the files it covers,
 * its assembled context — the rendered prompts and the cache coordinates its
 * findings are stored under — and the collection session the
 * `record_vulnerability` calls land in.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
