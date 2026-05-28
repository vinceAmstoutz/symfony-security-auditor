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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ControllerAccessControlParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\FormBindingParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\VoterCapabilityParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullControllerAccessControlParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullVoterCapabilityParser;

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
            $auditContext->setMapping(SymfonyMapping::create());

            return;
        }

        $controllers = array_values(array_filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isController()));
        $entities = array_values(array_filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isEntity()));
        $voters = array_values(array_filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isVoter()));
        $repositories = array_values(array_filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isRepository()));
        $forms = array_values(array_filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isForm()));
        $services = array_values(array_filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isService()));
        $templates = array_values(array_filter($files, static fn (ProjectFile $projectFile): bool => $projectFile->isTemplate()));

        [$routeAccessMap, $firewallRules] = $this->extractSecurityConfig($files);
        $routeAccessControls = $this->parseControllerAccessControls($controllers);
        $voterCapabilities = $this->parseVoterCapabilities($voters);
        $formBindings = $this->parseFormBindings($controllers);

        $symfonyMapping = SymfonyMapping::create(
            controllers: $controllers,
            entities: $entities,
            voters: $voters,
            repositories: $repositories,
            forms: $forms,
            services: $services,
            templates: $templates,
            routeAccessMap: $routeAccessMap,
            firewallRules: $firewallRules,
            routeAccessControls: $routeAccessControls,
            voterCapabilities: $voterCapabilities,
            formBindings: $formBindings,
        );

        $auditContext->setMapping($symfonyMapping);
        $auditContext->setMeta('mapping.controllers', \count($controllers));
        $auditContext->setMeta('mapping.entities', \count($entities));
        $auditContext->setMeta('mapping.voters', \count($voters));
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
