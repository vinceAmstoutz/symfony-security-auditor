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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool;

use Override;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;

/**
 * Builds a fresh ToolRegistry pre-loaded with the project's scanned files, so
 * tools like read_file / grep / list_files can answer the LLM's questions
 * without re-walking the filesystem.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyToolRegistryFactory implements ToolRegistryFactoryInterface
{
    public function __construct(
        private LoggerInterface $logger,
        private AdvisoryDatabaseInterface $advisoryDatabase,
    ) {}

    #[Override]
    public function forProjectFiles(array $projectFiles): ToolRegistry
    {
        return new ToolRegistry(
            tools: [
                new ReadFileTool($projectFiles),
                new GrepTool($projectFiles),
                new ListFilesTool($projectFiles),
                new LookupAdvisoryTool($this->advisoryDatabase),
            ],
            logger: $this->logger,
        );
    }
}
