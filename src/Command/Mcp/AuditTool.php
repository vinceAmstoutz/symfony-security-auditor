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

use Mcp\Exception\ToolCallException;
use Symfony\Component\Filesystem\Path;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase\RunAuditUseCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AuditedProjectPathHolder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\InvalidProjectPathException;

/** @internal not part of the BC promise — the MCP tool *name* (`audit`) is public, but the PHP class itself is for internal use only. */
final readonly class AuditTool
{
    public function __construct(
        private RunAuditUseCase $runAuditUseCase,
        private ReportRendererInterface $reportRenderer,
        private AuditedProjectPathHolder $auditedProjectPathHolder,
    ) {}

    /**
     * `mcp/sdk` answers a tool that throws anything but its own
     * `ToolCallException` with a bare "Error while executing tool", so every
     * failure — a relative path, an exhausted budget, a refused credential — is
     * rethrown as one, and its reason reaches the client that asked.
     *
     * @throws ToolCallException
     */
    public function audit(string $path): string
    {
        try {
            return $this->reportRenderer->render($this->runAuditUseCase->execute($this->canonicalPath($path)));
        } catch (Throwable $throwable) {
            throw $this->toolCallFailure($throwable);
        }
    }

    private function toolCallFailure(Throwable $throwable): ToolCallException
    {
        return new ToolCallException($throwable->getMessage(), previous: $throwable);
    }

    /**
     * @throws InvalidProjectPathException
     */
    private function canonicalPath(string $path): string
    {
        if (!Path::isAbsolute($path)) {
            throw InvalidProjectPathException::forNonAbsolutePath($path);
        }

        $canonicalPath = Path::canonicalize($path);
        $this->auditedProjectPathHolder->set($canonicalPath);

        return $canonicalPath;
    }
}
