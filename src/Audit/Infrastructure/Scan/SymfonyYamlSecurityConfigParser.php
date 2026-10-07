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
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProductionAwareSecurityConfigParserInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SymfonyYamlSecurityConfigParser implements ProductionAwareSecurityConfigParserInterface
{
    private const string PRODUCTION_ENVIRONMENT_BLOCK = 'when@prod';

    public function __construct(
        private LoggerInterface $logger = new NullLogger(),
        private AccessControlRequirementReader $accessControlRequirementReader = new AccessControlRequirementReader(),
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

    /**
     * The kernel reads `config/packages/security.yaml` in every environment
     * and what sits under `config/packages/prod/` in production only.
     */
    #[Override]
    public function isLoadedInProduction(string $relativePath): bool
    {
        return 1 === preg_match('~\Aconfig/packages/(?:prod/.+|security)\.ya?ml\z~', $relativePath);
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
        $entries = $section['access_control'] ?? null;
        if (!\is_array($entries)) {
            return $routeAccessMap;
        }

        foreach ($entries as $entry) {
            $routeAccessMap = $this->recordAccessControlEntry($this->mapOf($entry), $routeAccessMap);
        }

        return $routeAccessMap;
    }

    /**
     * @param array<string, mixed>        $entry
     * @param array<string, list<string>> $routeAccessMap
     *
     * @return array<string, list<string>>
     */
    private function recordAccessControlEntry(array $entry, array $routeAccessMap): array
    {
        $target = $this->targetOf($entry);
        if (null === $target || !$this->accessControlRequirementReader->hasAnyRequirementKey($entry)) {
            return $routeAccessMap;
        }

        $requirements = $this->accessControlRequirementReader->requirementsOf($entry);

        if (\array_key_exists($target, $routeAccessMap)) {
            $orRequirements = [] === $requirements ? [self::PUBLIC_ACCESS_MARKER] : $requirements;
            $routeAccessMap[$target][] = \sprintf('or: %s', implode(', ', $orRequirements));

            return $routeAccessMap;
        }

        $routeAccessMap[$target] = [] === $requirements ? [self::PUBLIC_ACCESS_MARKER] : $requirements;

        return $routeAccessMap;
    }

    /**
     * The `security` blocks of the document the production kernel reads: the
     * root one plus the `when@prod` override — a `when@test` or `when@dev`
     * block protects nothing in production. A bare root-level
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

        foreach ($document as $key => $value) {
            $block = $this->securityBlockOf($key, $value);
            if (null !== $block) {
                $sections[] = $block;
            }
        }

        return $sections;
    }

    private function parseYaml(string $configContent): mixed
    {
        try {
            return Yaml::parse($configContent);
        } catch (ParseException $parseException) {
            $this->logger->debug('Skipping unparseable YAML during security-config mapping', [
                'error' => $parseException->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * @return ?array<string, mixed>
     */
    private function securityBlockOf(string $key, mixed $value): ?array
    {
        if ('security' === $key) {
            return \is_array($value) ? $this->mapOf($value) : null;
        }

        if (self::PRODUCTION_ENVIRONMENT_BLOCK !== $key) {
            return null;
        }

        $security = $this->mapOf($value)['security'] ?? null;

        return \is_array($security) ? $this->mapOf($security) : null;
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
