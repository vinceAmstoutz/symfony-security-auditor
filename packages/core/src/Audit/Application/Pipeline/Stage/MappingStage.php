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
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuthorizationRuleCapability;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\EntrypointAccessControl;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AccessControlConfigParserInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\AuthorizationRuleParserInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\EntrypointAccessControlParserInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;

/**
 * `config/services.php` always aliases the four parser ports to their
 * `PhpParser*`/`SymfonyYamlSecurityConfigParser` implementations, so they are
 * required here rather than falling back to a Null* default.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class MappingStage implements StageInterface
{
    public function __construct(
        private LoggerInterface $logger,
        private EntrypointAccessControlParserInterface $entrypointAccessControlParser,
        private AuthorizationRuleParserInterface $authorizationRuleParser,
        private FormBindingParserInterface $formBindingParser,
        private AccessControlConfigParserInterface $accessControlConfigParser,
    ) {}

    #[Override]
    public function name(): string
    {
        return BuiltInStageName::Mapping->value;
    }

    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $files = $auditContext->mappingFiles();

        if ([] === $files) {
            $this->logger->warning('No files to map');
            $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromFiles([]), new AccessControlMap()));

            return;
        }

        $projectFileInventory = ProjectFileInventory::fromFiles($files);
        $entrypointFiles = $this->entrypointFiles($files);

        [$routeAccessMap, $perimeterRules] = $this->extractAccessControlConfig($files);
        $entrypointAccessControls = $this->parseEntrypointAccessControls($entrypointFiles);
        $authorizationRules = $this->parseAuthorizationRules($projectFileInventory->authorizationRules());
        $formBindings = $this->parseFormBindings($entrypointFiles);

        $symfonyMapping = SymfonyMapping::of(
            $projectFileInventory,
            new AccessControlMap(
                $routeAccessMap,
                $perimeterRules,
                $entrypointAccessControls,
                $authorizationRules,
                $formBindings,
            ),
        );

        $auditContext->setMapping($symfonyMapping);
        $auditContext->setMeta('mapping.controllers', \count($projectFileInventory->entrypoints()));
        $auditContext->setMeta('mapping.entities', \count($projectFileInventory->domainModels()));
        $auditContext->setMeta('mapping.voters', \count($projectFileInventory->authorizationRules()));
        $auditContext->setMeta('mapping.no_voter_controllers', \count($symfonyMapping->toApplicationSecurityMap()->entrypointsWithoutAuthorizationRule()));
        $auditContext->setMeta('mapping.routes', \count($entrypointAccessControls));
        $auditContext->setMeta('mapping.routes_without_access_check', \count($symfonyMapping->controllersWithoutAccessCheck()));
        $auditContext->setMeta('mapping.voter_capabilities', \count($authorizationRules));
        $auditContext->setMeta('mapping.form_bindings', \count($formBindings));

        $this->logger->info('Mapping complete', [
            'summary' => $symfonyMapping->toSummary(),
            'unprotected_controllers' => \count($symfonyMapping->toApplicationSecurityMap()->entrypointsWithoutAuthorizationRule()),
            'routes_without_access_check' => \count($symfonyMapping->controllersWithoutAccessCheck()),
            'voter_capabilities' => \count($authorizationRules),
            'form_bindings' => \count($formBindings),
        ]);
    }

    /**
     * A `#[AsLiveComponent]`/`#[ApiResource]` file classifies as its own
     * dedicated {@see ProjectFileType} (to keep its specialized attacker-skill
     * treatment) even when it also extends `AbstractController` — so
     * `ProjectFileInventory::controllers()` alone would miss its routed,
     * access-controlled actions.
     *
     * @param list<ProjectFile> $files
     *
     * @return list<ProjectFile>
     */
    private function entrypointFiles(array $files): array
    {
        return array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => $projectFile->fileType()->isControllerLike(),
        ));
    }

    /**
     * @param list<ProjectFile> $controllers
     *
     * @return list<EntrypointAccessControl>
     */
    private function parseEntrypointAccessControls(array $controllers): array
    {
        $entries = [];

        foreach ($controllers as $controller) {
            $entries = [...$entries, ...$this->entrypointAccessControlParser->parse($controller)];
        }

        return $entries;
    }

    /**
     * @param list<ProjectFile> $voters
     *
     * @return list<AuthorizationRuleCapability>
     */
    private function parseAuthorizationRules(array $voters): array
    {
        $entries = [];

        foreach ($voters as $voter) {
            $capability = $this->authorizationRuleParser->parse($voter);
            if ($capability instanceof AuthorizationRuleCapability) {
                $entries[] = $capability;
            }
        }

        return $entries;
    }

    /**
     * @param list<ProjectFile> $controllers
     *
     * @return list<FormBinding>
     */
    private function parseFormBindings(array $controllers): array
    {
        $entries = [];

        foreach ($controllers as $controller) {
            $entries = [...$entries, ...$this->formBindingParser->parse($controller)];
        }

        return $entries;
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return array{array<string, list<string>>, list<string>}
     */
    private function extractAccessControlConfig(array $files): array
    {
        $routeAccessMap = [];
        $perimeterRules = [];

        foreach ($files as $file) {
            if (!$file->isConfiguration()) {
                continue;
            }

            $content = $file->content();
            $routeAccessMap = $this->mergeRouteAccessMaps($routeAccessMap, $this->accessControlConfigParser->parseEntrypointAccessMap($content));
            $perimeterRules = [...$perimeterRules, ...$this->accessControlConfigParser->parsePerimeterRules($content)];
        }

        return [$routeAccessMap, $perimeterRules];
    }

    /**
     * Mirrors {@see SymfonyYamlSecurityConfigParser::recordAccessControlEntry()}'s
     * first-match-wins semantics across config files: a rule for a path already
     * covered by an earlier file is appended as an `or: …` requirement instead of
     * replacing it, so no file's rule is silently dropped.
     *
     * @param array<string, list<string>> $routeAccessMap
     * @param array<string, list<string>> $incoming
     *
     * @return array<string, list<string>>
     */
    private function mergeRouteAccessMaps(array $routeAccessMap, array $incoming): array
    {
        foreach ($incoming as $target => $requirements) {
            if (\array_key_exists($target, $routeAccessMap)) {
                $routeAccessMap[$target][] = \sprintf('or: %s', implode(', ', $requirements));

                continue;
            }

            $routeAccessMap[$target] = $requirements;
        }

        return $routeAccessMap;
    }
}
