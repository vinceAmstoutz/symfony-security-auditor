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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp;

use Mcp\Server;
use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class McpServerFactory implements McpServerFactoryInterface
{
    private const string SERVER_NAME = 'symfony-security-auditor';

    private const string AUDIT_TOOL_NAME = 'audit';

    private const string AUDIT_TOOL_DESCRIPTION = 'Run the AI-powered multi-agent security audit on a Symfony project directory and return the JSON report of the vulnerabilities found.';

    public function __construct(
        private AuditTool $auditTool,
        private ReportPackage $reportPackage,
    ) {}

    #[Override]
    public function create(): Server
    {
        return Server::builder()
            ->setServerInfo(self::SERVER_NAME, $this->reportPackage->version())
            ->addTool(
                fn (string $path): string => $this->auditTool->audit($path),
                self::AUDIT_TOOL_NAME,
                description: self::AUDIT_TOOL_DESCRIPTION,
                inputSchema: [
                    'type' => 'object',
                    'properties' => [
                        'path' => [
                            'type' => 'string',
                            'description' => 'Absolute path to the Symfony project directory to audit.',
                        ],
                    ],
                    'required' => ['path'],
                ],
            )
            ->build();
    }
}
