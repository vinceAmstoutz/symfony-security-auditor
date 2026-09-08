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

namespace VinceAmstoutz\SecurityAuditor\Audit\Application\Pipeline\Stage;

use Override;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ApplicationSecurityMap;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuthorizationRuleCapability;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\EntrypointAccessControl;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Pipeline\StageInterface;

/**
 * With `audit.since_closure: direct`, widens a `--since` diff-mode run's audited
 * file set with the first-degree dependents of any changed authorization rule —
 * the entrypoints guarded by an attribute that rule covers, whichever guard form
 * the profile reported — so a rule edit that silently weakens an unrelated
 * entrypoint's access control is still caught. Runs after `MappingStage`, which
 * builds the full-project `AccessControlMap` it reads regardless of diff
 * filtering.
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

        $securityMap = $auditContext->securityMap();
        if (!$securityMap instanceof ApplicationSecurityMap) {
            return;
        }

        $projectFiles = $auditContext->projectFiles();
        $changedPaths = array_flip(array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $projectFiles));
        $changedRuleAttributes = $this->changedRuleAttributes($changedPaths, $securityMap->authorizationRules());
        $guardedPaths = $this->guardedEntrypointPaths($securityMap->entrypointAccessControls(), $changedRuleAttributes);

        $newPaths = array_values(array_filter($guardedPaths, static fn (string $path): bool => !\array_key_exists($path, $changedPaths)));

        $added = $this->resolveFiles($newPaths, $auditContext->mappingFiles());
        if ([] === $added) {
            return;
        }

        $auditContext->setProjectFiles([...$projectFiles, ...$added]);
        $auditContext->setMeta('dependency_expansion.files_added', \count($added));

        $this->logger->info('Dependency expansion complete', [
            'changed_voter_attributes' => $changedRuleAttributes,
            'files_added' => \count($added),
        ]);
    }

    /**
     * @param array<string, int>                $changedPaths
     * @param list<AuthorizationRuleCapability> $authorizationRules
     *
     * @return list<string>
     */
    private function changedRuleAttributes(array $changedPaths, array $authorizationRules): array
    {
        $attributes = [];
        foreach ($authorizationRules as $authorizationRule) {
            if (\array_key_exists($authorizationRule->filePath(), $changedPaths)) {
                $attributes = [...$attributes, ...$authorizationRule->supportedAttributes()];
            }
        }

        return array_values(array_unique($attributes));
    }

    /**
     * @param list<EntrypointAccessControl> $entrypointAccessControls
     * @param list<string>                  $changedRuleAttributes
     *
     * @return list<string>
     */
    private function guardedEntrypointPaths(array $entrypointAccessControls, array $changedRuleAttributes): array
    {
        $paths = [];
        foreach ($entrypointAccessControls as $entrypointAccessControl) {
            if ([] !== array_intersect($entrypointAccessControl->guardAttributes(), $changedRuleAttributes)) {
                $paths[] = $entrypointAccessControl->filePath();
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
