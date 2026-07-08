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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ControllerAccessControlParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecurityConfigParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\VoterCapabilityParserInterface;

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
        private ControllerAccessControlParserInterface $controllerAccessControlParser,
        private VoterCapabilityParserInterface $voterCapabilityParser,
        private FormBindingParserInterface $formBindingParser,
        private SecurityConfigParserInterface $securityConfigParser,
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
        $controllerLikeFiles = $this->controllerLikeFiles($files);

        [$routeAccessMap, $firewallRules] = $this->extractSecurityConfig($files);
        $routeAccessControls = $this->parseControllerAccessControls($controllerLikeFiles);
        $voterCapabilities = $this->parseVoterCapabilities($projectFileInventory->voters());
        $formBindings = $this->parseFormBindings($controllerLikeFiles);

        $symfonyMapping = SymfonyMapping::of(
            $projectFileInventory,
            new AccessControlMap(
                $routeAccessMap,
                $firewallRules,
                $routeAccessControls,
                $voterCapabilities,
                $formBindings,
            ),
        );

        $auditContext->setMapping($symfonyMapping);
        $auditContext->setMeta('mapping.controllers', \count($projectFileInventory->controllers()));
        $auditContext->setMeta('mapping.entities', \count($projectFileInventory->entities()));
        $auditContext->setMeta('mapping.voters', \count($projectFileInventory->voters()));
        $auditContext->setMeta('mapping.no_voter_controllers', \count($symfonyMapping->controllersWithoutVoters()));
        $auditContext->setMeta('mapping.routes', \count($routeAccessControls));
        $auditContext->setMeta('mapping.routes_without_access_check', \count($symfonyMapping->controllersWithoutAccessCheck()));
        $auditContext->setMeta('mapping.voter_capabilities', \count($voterCapabilities));
        $auditContext->setMeta('mapping.form_bindings', \count($formBindings));

        $this->logger->info('Mapping complete', [
            'summary' => $symfonyMapping->toSummary(),
            'unprotected_controllers' => \count($symfonyMapping->controllersWithoutVoters()),
            'routes_without_access_check' => \count($symfonyMapping->controllersWithoutAccessCheck()),
            'voter_capabilities' => \count($voterCapabilities),
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
    private function controllerLikeFiles(array $files): array
    {
        return array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => $projectFile->fileType()->isControllerLike(),
        ));
    }

    /**
     * @param list<ProjectFile> $controllers
     *
     * @return list<RouteAccessControl>
     */
    private function parseControllerAccessControls(array $controllers): array
    {
        $entries = [];

        foreach ($controllers as $controller) {
            $entries = [...$entries, ...$this->controllerAccessControlParser->parse($controller)];
        }

        return $entries;
    }

    /**
     * @param list<ProjectFile> $voters
     *
     * @return list<VoterCapability>
     */
    private function parseVoterCapabilities(array $voters): array
    {
        $entries = [];

        foreach ($voters as $voter) {
            $capability = $this->voterCapabilityParser->parse($voter);
            if ($capability instanceof VoterCapability) {
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
    private function extractSecurityConfig(array $files): array
    {
        $routeAccessMap = [];
        $firewallRules = [];

        foreach ($files as $file) {
            if (!$file->isConfiguration()) {
                continue;
            }

            $content = $file->content();
            $routeAccessMap = $this->mergeRouteAccessMaps($routeAccessMap, $this->securityConfigParser->parseAccessControl($content));
            $firewallRules = [...$firewallRules, ...$this->securityConfigParser->parseFirewallRules($content)];
        }

        return [$routeAccessMap, $firewallRules];
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
