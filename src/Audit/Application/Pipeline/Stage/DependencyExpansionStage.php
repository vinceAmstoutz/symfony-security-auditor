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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScanPathFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ApplicationSecurityMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CandidateFindingSourceInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * With `audit.since_closure: direct`, adds to a `--since` run the controllers
 * guarded by an attribute a changed voter supports (through `#[IsGranted]` on
 * the method or class, or a `denyAccessUnlessGranted()` or `isGranted()`
 * call), within the run's `--path` scope. Queues the static candidates of
 * those it adds for review. Runs after `MappingStage`, whose
 * `AccessControlMap` covers the whole project.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class DependencyExpansionStage implements StageInterface
{
    private const string DIRECT = 'direct';

    public function __construct(
        private LoggerInterface $logger,
        private string $sinceClosure = 'none',
        private ?CandidateFindingSourceInterface $candidateFindingSource = null,
        private ?ProgressReporterInterface $progressReporter = null,
    ) {}

    #[Override]
    public function name(): string
    {
        return BuiltInStageName::DependencyExpansion->value;
    }

    #[Override]
    public function process(AuditContext $auditContext): void
    {
        if (!$this->widens($auditContext->diffSinceRef())) {
            return;
        }

        $securityMap = $auditContext->securityMap();
        if (!$securityMap instanceof ApplicationSecurityMap) {
            return;
        }

        $projectFiles = $auditContext->projectFiles();
        $changedPaths = array_flip(array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $projectFiles));
        $changedVoterAttributes = $this->changedVoterAttributes($changedPaths, $securityMap->authorizationRules());
        $guardedPaths = $this->guardedControllerPaths($securityMap->entrypointAccessControls(), $changedVoterAttributes, $this->voterConstantValues($securityMap->authorizationRules()));

        $newPaths = array_values(array_filter($guardedPaths, static fn (string $path): bool => !\array_key_exists($path, $changedPaths)));

        $added = $this->resolveFiles($newPaths, ScanPathFilter::apply($auditContext->mappingFiles(), $auditContext->scanPaths()));
        if ([] === $added) {
            return;
        }

        $auditContext->setProjectFiles([...$projectFiles, ...$added]);
        $auditContext->setMeta('dependency_expansion.files_added', \count($added));
        StaticCandidateQueue::queue($added, $auditContext, $this->candidateFindingSource, $this->progressReporter);

        $this->logger->info('Dependency expansion complete', [
            'changed_voter_attributes' => $changedVoterAttributes,
            'files_added' => \count($added),
        ]);
    }

    /**
     * Whether a run against this git ref audits more than its diff.
     */
    public function widens(?string $diffSinceRef): bool
    {
        return self::DIRECT === $this->sinceClosure && null !== $diffSinceRef;
    }

    /**
     * @param array<string, int>    $changedPaths
     * @param list<VoterCapability> $voterCapabilities
     *
     * @return list<string>
     */
    private function changedVoterAttributes(array $changedPaths, array $voterCapabilities): array
    {
        $attributes = [];
        foreach ($voterCapabilities as $voterCapability) {
            if (\array_key_exists($voterCapability->filePath(), $changedPaths)) {
                $attributes = [...$attributes, ...$voterCapability->supportedAttributes()];
            }
        }

        return array_values(array_unique($attributes));
    }

    /**
     * Maps each voter constant, keyed `Fully\Qualified\Class::NAME` as a guard
     * names it, to the string it holds.
     *
     * @param list<VoterCapability> $voterCapabilities
     *
     * @return array<string, string>
     */
    private function voterConstantValues(array $voterCapabilities): array
    {
        $values = [];
        foreach ($voterCapabilities as $voterCapability) {
            foreach ($voterCapability->constantValues() as $name => $value) {
                $values[\sprintf('%s::%s', $voterCapability->className(), $name)] = $value;
            }
        }

        return $values;
    }

    /**
     * @param list<RouteAccessControl> $routeAccessControls
     * @param list<string>             $changedVoterAttributes
     * @param array<string, string>    $voterConstantValues
     *
     * @return list<string>
     */
    private function guardedControllerPaths(array $routeAccessControls, array $changedVoterAttributes, array $voterConstantValues): array
    {
        $paths = [];
        foreach ($routeAccessControls as $routeAccessControl) {
            $guards = [...$routeAccessControl->guardAttributes(), ...array_intersect_key($voterConstantValues, array_flip($routeAccessControl->guardConstants()))];
            if ([] !== array_intersect($guards, $changedVoterAttributes)) {
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
