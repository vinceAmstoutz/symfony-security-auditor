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

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AdvisoryDatabaseInterface;

/**
 * Builds a fresh ToolRegistry pre-loaded with the project's scanned files, so
 * tools like read_file / grep / list_files can answer the LLM's questions
 * without re-walking the filesystem.
 */
final readonly class SymfonyToolRegistryFactory implements ToolRegistryFactoryInterface
{
    public function __construct(
        private LoggerInterface $logger,
        private AdvisoryDatabaseInterface $advisoryDatabase,
    ) {}

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
