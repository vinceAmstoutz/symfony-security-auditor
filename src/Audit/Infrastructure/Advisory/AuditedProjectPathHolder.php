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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

/**
 * Mutable runtime carrier (same pattern as `ProgressReporterHolder`) bridging
 * a container-time default — `kernel.project_dir` — and the project path the
 * audit command actually targets, which is only known once its `project-path`
 * argument is resolved.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class AuditedProjectPathHolder
{
    private ?string $projectPath = null;

    public function __construct(private readonly string $defaultProjectPath) {}

    public function set(string $projectPath): void
    {
        $this->projectPath = $projectPath;
    }

    public function path(): string
    {
        return $this->projectPath ?? $this->defaultProjectPath;
    }
}
