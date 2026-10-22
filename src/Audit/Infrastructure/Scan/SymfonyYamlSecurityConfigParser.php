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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use Override;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlRule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProductionConfiguration;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ImportAwareSecurityConfigParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RuleOrderAwareSecurityConfigParserInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\Exception\UnreadableYamlException;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SymfonyYamlSecurityConfigParser implements ImportAwareSecurityConfigParserInterface, RuleOrderAwareSecurityConfigParserInterface
{
    private const string PRODUCTION_ENVIRONMENT_BLOCK = 'when@prod';

    public function __construct(
        private LoggerInterface $logger = new NullLogger(),
        private AccessControlRequirementReader $accessControlRequirementReader = new AccessControlRequirementReader(),
        private KernelConfigurationLoader $kernelConfigurationLoader = new KernelConfigurationLoader(),
        private RepositoryYamlReader $repositoryYamlReader = new RepositoryYamlReader(),
    ) {}

    #[Override]
    public function parseAccessControl(string $configContent): array
    {
        $routeAccessMap = [];
        foreach ($this->securitySections($configContent) as $section) {
            $routeAccessMap = $this->accessControlOf($section, $routeAccessMap);
        }

        return $routeAccessMap;
    }

    #[Override]
    public function isLoadedInProduction(string $relativePath): bool
    {
        return KernelConfigurationLoader::isLoadedByTheKernel($relativePath);
    }

    #[Override]
    public function loadRank(string $relativePath): int
    {
        return KernelConfigurationLoader::loadRank($relativePath);
    }

    #[Override]
    public function productionConfiguration(array $files, array $scanPaths): ProductionConfiguration
    {
        return $this->kernelConfigurationLoader->filesInLoadOrder($files, $scanPaths);
    }

    /**
     * Every rule with a path or a route, those that check nothing included.
     */
    #[Override]
    public function parseAccessControlRules(string $configContent): array
    {
        $accessControlRules = [];
        foreach ($this->securitySections($configContent) as $section) {
            $accessControlRules = [...$accessControlRules, ...$this->accessControlRulesOf($section)];
        }

        return $accessControlRules;
    }

    #[Override]
    public function parseFirewallRules(string $configContent): array
    {
        $rules = [];
        foreach ($this->securitySections($configContent) as $section) {
            foreach ($this->mapOf($section['firewalls'] ?? null) as $name => $firewall) {
                $rules[] = $this->firewallRule($name, $this->mapOf($firewall));
            }
        }

        return $rules;
    }

    /**
     * Public marker recorded for an `access_control` entry that matches but
     * carries no requirement at all (e.g. an explicit `roles: []`) — a
     * deliberate "this path is public" rule. Recording it (instead of
     * skipping the entry) preserves first-match-wins: a later rule for the
     * same path must not silently present as the sole governing rule when an
     * earlier, unconditional public rule already claims the path.
     */
    private const string PUBLIC_ACCESS_MARKER = 'PUBLIC';

    /**
     * Symfony evaluates `access_control` first-match-wins, so a later rule for
     * an already-seen path applies only to requests the earlier rule's
     * constraints (methods, ips, …) did not match — it is appended as a single
     * `or: …` requirement instead of silently replacing the earlier rule.
     *
     * @param array<string, mixed>        $section
     * @param array<string, list<string>> $routeAccessMap
     *
     * @return array<string, list<string>>
     */
    private function accessControlOf(array $section, array $routeAccessMap): array
    {
        foreach ($this->recordedEntriesOf($section) as [$target, $requirements]) {
            if (\array_key_exists($target, $routeAccessMap)) {
                $routeAccessMap[$target][] = \sprintf('or: %s', implode(', ', $requirements));

                continue;
            }

            $routeAccessMap[$target] = $requirements;
        }

        return $routeAccessMap;
    }

    /**
     * @param array<string, mixed> $section
     *
     * @return list<array{string, list<string>}> the target and requirements of each entry that has both, in the order declared
     */
    private function recordedEntriesOf(array $section): array
    {
        $entries = $section['access_control'] ?? null;

        $recordedEntries = [];
        foreach (\is_array($entries) ? $entries : [] as $entry) {
            $recordedEntries[] = $this->recordAccessControlEntry($this->mapOf($entry));
        }

        return array_merge(...$recordedEntries);
    }

    /**
     * @param array<string, mixed> $entry
     *
     * @return list<array{string, list<string>}> the entry's target and requirements, or none for an entry without a target or a requirement
     */
    private function recordAccessControlEntry(array $entry): array
    {
        $target = $this->targetOf($entry);
        if (null === $target || !$this->accessControlRequirementReader->hasAnyRequirementKey($entry)) {
            return [];
        }

        $requirements = $this->accessControlRequirementReader->requirementsOf($entry);

        return [[$target, [] === $requirements ? [self::PUBLIC_ACCESS_MARKER] : $requirements]];
    }

    /**
     * @param array<string, mixed> $section
     *
     * @return list<AccessControlRule>
     */
    private function accessControlRulesOf(array $section): array
    {
        $entries = $section['access_control'] ?? null;

        $accessControlRules = [];
        foreach (\is_array($entries) ? $entries : [] as $entry) {
            $accessControlRules[] = $this->accessControlRuleOf($this->mapOf($entry));
        }

        return array_merge(...$accessControlRules);
    }

    /**
     * @param array<string, mixed> $entry
     *
     * @return list<AccessControlRule> the rule, or none for an entry without a path or a route
     */
    private function accessControlRuleOf(array $entry): array
    {
        $target = $this->targetOf($entry);
        if (null === $target) {
            return [];
        }

        return [new AccessControlRule($target, $this->accessControlRequirementReader->methodsOf($entry), $this->accessControlRequirementReader->restricts($entry))];
    }

    /**
     * The `security` blocks of the document the production kernel reads, in the
     * order it loads them: the root one, then the `when@prod` override,
     * wherever the document writes them — a `when@test` or `when@dev` block
     * protects nothing in production. A bare root-level
     * `access_control`/`firewalls` document (an imported partial) also counts
     * as a section.
     *
     * @return list<array<string, mixed>>
     */
    private function securitySections(string $configContent): array
    {
        $document = $this->mapOf($this->parseYaml($configContent));

        $sections = [];
        if (\array_key_exists('access_control', $document) || \array_key_exists('firewalls', $document)) {
            $sections[] = $document;
        }

        $productionOverride = $this->mapOf($document[self::PRODUCTION_ENVIRONMENT_BLOCK] ?? null);
        foreach ([$document['security'] ?? null, $productionOverride['security'] ?? null] as $security) {
            if (\is_array($security)) {
                $sections[] = $this->mapOf($security);
            }
        }

        return $sections;
    }

    private function parseYaml(string $configContent): mixed
    {
        try {
            return $this->repositoryYamlReader->read($configContent);
        } catch (UnreadableYamlException $unreadableYamlException) {
            $this->logger->debug('Skipping unparseable YAML during security-config mapping', [
                'error' => $unreadableYamlException->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * @param array<string, mixed> $entry
     */
    private function targetOf(array $entry): ?string
    {
        $rawPath = $entry['path'] ?? null;
        // A blank path becomes an empty PCRE pattern, which matches any route at all — never record it.
        $path = \is_string($rawPath) ? trim($rawPath) : '';
        if ('' !== $path) {
            return $path;
        }

        if (\is_string($entry['route'] ?? null)) {
            return \sprintf('route: %s', $entry['route']);
        }

        return null;
    }

    /**
     * @param array<string, mixed> $firewall
     */
    private function firewallRule(string $name, array $firewall): string
    {
        $base = \is_string($firewall['pattern'] ?? null) ? trim($firewall['pattern']) : $name;

        $flags = [];
        if (false === ($firewall['security'] ?? null)) {
            $flags[] = 'security: false';
        }

        if (true === ($firewall['stateless'] ?? null)) {
            $flags[] = 'stateless';
        }

        return [] === $flags ? $base : \sprintf('%s (%s)', $base, implode(', ', $flags));
    }

    /**
     * @return array<string, mixed>
     */
    private function mapOf(mixed $value): array
    {
        if (!\is_array($value)) {
            return [];
        }

        return array_filter($value, static fn (int|string $key): bool => \is_string($key), \ARRAY_FILTER_USE_KEY);
    }
}
