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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\VoterCapabilityParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullVoterCapabilityParser;

use function Symfony\Component\String\u;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class MappingStage implements StageInterface
{
    private ControllerAccessControlParserInterface $controllerAccessControlParser;

    private VoterCapabilityParserInterface $voterCapabilityParser;

    private FormBindingParserInterface $formBindingParser;

    public function __construct(
        private LoggerInterface $logger,
        ?ControllerAccessControlParserInterface $controllerAccessControlParser = null,
        ?VoterCapabilityParserInterface $voterCapabilityParser = null,
        ?FormBindingParserInterface $formBindingParser = null,
    ) {
        $this->controllerAccessControlParser = $controllerAccessControlParser ?? new NullControllerAccessControlParser();
        $this->voterCapabilityParser = $voterCapabilityParser ?? new NullVoterCapabilityParser();
        $this->formBindingParser = $formBindingParser ?? new NullFormBindingParser();
    }

    public function name(): string
    {
        return BuiltInStageName::Mapping->value;
    }

    public function process(AuditContext $auditContext): void
    {
        $files = $auditContext->projectFiles();

        if ([] === $files) {
            $this->logger->warning('No files to map');
            $auditContext->setMapping(SymfonyMapping::of(ProjectFileInventory::fromFiles([]), new AccessControlMap()));

            return;
        }

        $inventory = ProjectFileInventory::fromFiles($files);

        [$routeAccessMap, $firewallRules] = $this->extractSecurityConfig($files);
        $routeAccessControls = $this->parseControllerAccessControls($inventory->controllers());
        $voterCapabilities = $this->parseVoterCapabilities($inventory->voters());
        $formBindings = $this->parseFormBindings($inventory->controllers());

        $symfonyMapping = SymfonyMapping::of(
            $inventory,
            new AccessControlMap(
                $routeAccessMap,
                $firewallRules,
                $routeAccessControls,
                $voterCapabilities,
                $formBindings,
            ),
        );

        $auditContext->setMapping($symfonyMapping);
        $auditContext->setMeta('mapping.controllers', \count($inventory->controllers()));
        $auditContext->setMeta('mapping.entities', \count($inventory->entities()));
        $auditContext->setMeta('mapping.voters', \count($inventory->voters()));
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

            if (u($file->relativePath())->containsAny('security')) {
                $firewallRules = [...$firewallRules, ...$this->extractFirewallRules($content)];
            }

            $routeAccessMap = array_merge($routeAccessMap, $this->extractAccessControl($content));
        }

        return [$routeAccessMap, $firewallRules];
    }

    /**
     * @return list<string>
     */
    private function extractFirewallRules(string $content): array
    {
        preg_match_all('/pattern:\s*(.+)/m', $content, $matches);

        return array_map('trim', $matches[1]);
    }

    /**
     * @return array<string, list<string>>
     */
    private function extractAccessControl(string $content): array
    {
        if (!u($content)->containsAny('access_control')) {
            return [];
        }

        preg_match_all('/path:\s*(.+)\n\s+roles?:\s*(.+)/m', $content, $matches);

        $map = [];
        foreach ($matches[1] as $i => $pathRaw) {
            $path = u($pathRaw)->trim()->toString();
            $rolesRaw = $matches[2][$i] ?? '';
            $map[$path] = array_map('trim', explode(',', $rolesRaw));
        }

        return $map;
    }
}
