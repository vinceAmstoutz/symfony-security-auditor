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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Emits one `attacker.finding.recorded` progress event per finding a chunk
 * produced, so reporters can stream findings live as the attacker discovers
 * them. Shared by the sequential and concurrent chunk analyzers.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkFindingProgress
{
    /**
     * @param list<Vulnerability> $vulnerabilities
     */
    public static function report(ProgressReporterInterface $progressReporter, array $vulnerabilities): void
    {
        foreach ($vulnerabilities as $vulnerability) {
            $progressReporter->report(ProgressEvent::AttackerFindingRecorded->value, [
                'severity' => $vulnerability->severity()->value,
                'type' => $vulnerability->type()->value,
                'file' => $vulnerability->filePath(),
                'line' => $vulnerability->lineStart(),
            ]);
        }
    }
}
