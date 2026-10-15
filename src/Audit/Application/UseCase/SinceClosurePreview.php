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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\DependencyExpansionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

/**
 * The files a `--since` run audits once `audit.since_closure` widened its
 * diff, for the previews that run no pipeline — `--show-scanned` and
 * `--dry-run` — so they list and price what the run will send. The project
 * mapping is read only when the closure widens the run.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SinceClosurePreview
{
    public function __construct(
        private StageInterface $mappingStage,
        private DependencyExpansionStage $dependencyExpansionStage,
    ) {}

    /**
     * @param list<string>      $scanPaths    the run's `--path` values
     * @param list<ProjectFile> $changedFiles the files the git diff kept
     * @param list<ProjectFile> $mappingFiles the files the run reads the project mapping from
     *
     * @return list<ProjectFile>
     *
     * @throws InvalidAuditContextException
     */
    public function auditedFiles(string $projectPath, array $scanPaths, string $diffSinceRef, array $changedFiles, array $mappingFiles): array
    {
        if (!$this->dependencyExpansionStage->widens($diffSinceRef)) {
            return $changedFiles;
        }

        $auditContext = AuditContext::forProject($projectPath, $scanPaths, diffSinceRef: $diffSinceRef);
        $auditContext->setProjectFiles($changedFiles);
        $auditContext->setMappingFiles($mappingFiles);

        $this->mappingStage->process($auditContext);
        $this->dependencyExpansionStage->process($auditContext);

        return $auditContext->projectFiles();
    }
}
