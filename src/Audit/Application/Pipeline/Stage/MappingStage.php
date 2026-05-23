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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class MappingStage implements StageInterface
{
    public function __construct(
        private LoggerInterface $logger,
    ) {}

    public function name(): string
    {
        return 'mapping';
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
        );

        $auditContext->setMapping($symfonyMapping);
        $auditContext->setMeta('mapping.controllers', \count($controllers));
        $auditContext->setMeta('mapping.entities', \count($entities));
        $auditContext->setMeta('mapping.voters', \count($voters));
        $auditContext->setMeta('mapping.no_voter_controllers', \count($symfonyMapping->controllersWithoutVoters()));

        $this->logger->info('Mapping complete', [
            'summary' => $symfonyMapping->toSummary(),
            'unprotected_controllers' => \count($symfonyMapping->controllersWithoutVoters()),
        ]);
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

            if (str_contains($file->relativePath(), 'security')) {
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
        if (!str_contains($content, 'access_control')) {
            return [];
        }

        preg_match_all('/path:\s*(.+)\n\s+roles?:\s*(.+)/m', $content, $matches);

        $map = [];
        foreach ($matches[1] as $i => $pathRaw) {
            $path = trim($pathRaw);
            $rolesRaw = $matches[2][$i] ?? '';
            $map[$path] = array_map('trim', explode(',', $rolesRaw));
        }

        return $map;
    }
}
