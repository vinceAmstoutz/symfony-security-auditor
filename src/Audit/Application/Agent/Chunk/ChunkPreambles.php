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

/**
 * The context a chunk's user message is prefixed with: the risk markers of its
 * files, the findings rejected and the ones confirmed in earlier iterations,
 * and the candidates a first-pass model reported on its files.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkPreambles
{
    public function __construct(
        public string $markers,
        public string $rejected,
        public string $previous,
        public string $candidates,
    ) {}
}
