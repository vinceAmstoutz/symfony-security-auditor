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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage;

use Override;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

/**
 * With `audit.since_closure: direct`, widens a `--since` diff-mode run's
 * audited file set with the first-degree dependents of any changed voter —
 * the controllers guarded by an `#[IsGranted]` attribute the voter's
 * `supports()` accepts — so a voter edit that silently weakens an unrelated
 * controller's access control is still caught. Runs after `MappingStage`,
 * which builds the full-project `AccessControlMap` this stage reads from
 * regardless of diff filtering.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class DependencyExpansionStage implements StageInterface
{
    private const string DIRECT = 'direct';

    public function __construct(
        private LoggerInterface $logger,
        private string $sinceClosure = 'none',
    ) {}

    #[Override]
    public function name(): string
    {
        return BuiltInStageName::DependencyExpansion->value;
    }

    #[Override]
    public function process(AuditContext $auditContext): void
    {
        if (self::DIRECT !== $this->sinceClosure || null === $auditContext->diffSinceRef()) {
            return;
        }

        $mapping = $auditContext->mapping();
        if (!$mapping instanceof SymfonyMapping) {
            return;
        }

        $projectFiles = $auditContext->projectFiles();
        $changedVoterAttributes = $this->changedVoterAttributes($projectFiles, $mapping->voterCapabilities());
        if ([] === $changedVoterAttributes) {
            return;
        }

        $changedPaths = array_flip(array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $projectFiles));
        $guardedPaths = $this->guardedControllerPaths($mapping->routeAccessControls(), $changedVoterAttributes);
        $newPaths = array_values(array_filter($guardedPaths, static fn (string $path): bool => !\array_key_exists($path, $changedPaths)));

        $added = $this->resolveFiles($newPaths, $auditContext->mappingFiles());
        if ([] === $added) {
            return;
        }

        $auditContext->setProjectFiles([...$projectFiles, ...$added]);
        $auditContext->setMeta('dependency_expansion.files_added', \count($added));

        $this->logger->info('Dependency expansion complete', [
            'changed_voter_attributes' => $changedVoterAttributes,
            'files_added' => \count($added),
        ]);
    }

    /**
     * @param list<ProjectFile>     $projectFiles
     * @param list<VoterCapability> $voterCapabilities
     *
     * @return list<string>
     */
    private function changedVoterAttributes(array $projectFiles, array $voterCapabilities): array
    {
        $changedVoterPaths = array_flip(array_map(
            static fn (ProjectFile $projectFile): string => $projectFile->relativePath(),
            array_values(array_filter($projectFiles, static fn (ProjectFile $projectFile): bool => $projectFile->isVoter())),
        ));

        if ([] === $changedVoterPaths) {
            return [];
        }

        $attributes = [];
        foreach ($voterCapabilities as $voterCapability) {
            if (\array_key_exists($voterCapability->filePath(), $changedVoterPaths)) {
                $attributes = [...$attributes, ...$voterCapability->supportedAttributes()];
            }
        }

        return array_values(array_unique($attributes));
    }

    /**
     * @param list<RouteAccessControl> $routeAccessControls
     * @param list<string>             $changedVoterAttributes
     *
     * @return list<string>
     */
    private function guardedControllerPaths(array $routeAccessControls, array $changedVoterAttributes): array
    {
        $paths = [];
        foreach ($routeAccessControls as $routeAccessControl) {
            if ([] !== array_intersect($routeAccessControl->methodLevelIsGranted(), $changedVoterAttributes)) {
                $paths[] = $routeAccessControl->filePath();
            }
        }

        return array_values(array_unique($paths));
    }

    /**
     * @param list<string>      $paths
     * @param list<ProjectFile> $mappingFiles
     *
     * @return list<ProjectFile>
     */
    private function resolveFiles(array $paths, array $mappingFiles): array
    {
        $filesByPath = [];
        foreach ($mappingFiles as $mappingFile) {
            $filesByPath[$mappingFile->relativePath()] = $mappingFile;
        }

        $resolved = [];
        foreach ($paths as $path) {
            if (\array_key_exists($path, $filesByPath)) {
                $resolved[] = $filesByPath[$path];
            }
        }

        return $resolved;
    }
}
