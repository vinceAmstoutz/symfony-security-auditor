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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * Records attacker coverage for every file in a chunk under a single status.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkCoverageRecorder
{
    /**
     * @param list<ProjectFile> $chunk
     */
    public static function record(array $chunk, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($chunk as $file) {
            $coverageRecorder->recordCoverage(AgentRole::Attacker->value, $file->relativePath(), $status);
        }
    }
}
