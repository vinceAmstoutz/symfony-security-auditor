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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;

/**
 * The scan/chunk/report infrastructure the attacker agent coordinates around
 * LLM analysis. `staticPreScanner` and `progressReporter` are always resolved
 * by DI — `SymfonySecurityAuditorBundle` aliases both to a Null* or real
 * implementation unconditionally — so they are required here. `fileChunker`
 * and `toolRegistryFactory` stay nullable with in-agent defaults.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AttackerScanCollaborators
{
    public function __construct(
        public AttackerCacheInterface $attackerCache,
        public StaticPreScannerInterface $staticPreScanner,
        public ProgressReporterInterface $progressReporter,
        public ?FileChunker $fileChunker = null,
        public ?ToolRegistryFactoryInterface $toolRegistryFactory = null,
    ) {}
}
