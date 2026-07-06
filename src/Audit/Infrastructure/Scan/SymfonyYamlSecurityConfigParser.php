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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SecurityConfigParserInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SymfonyYamlSecurityConfigParser implements SecurityConfigParserInterface
{
    public function __construct(
        private LoggerInterface $logger = new NullLogger(),
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
            $entryMap = $this->mapOf($entry);
            $target = $this->targetOf($entryMap);
            $requirements = $this->requirementsOf($entryMap);
            if (null === $target) {
                continue;
            }

            if ([] === $requirements) {
                continue;
            }

            if (\array_key_exists($target, $routeAccessMap)) {
                $routeAccessMap[$target][] = \sprintf('or: %s', implode(', ', $requirements));

                continue;
            }

            $routeAccessMap[$target] = $requirements;
        }

        return $routeAccessMap;
    }

    /**
     * The `security` blocks of the document: the root one plus every
     * environment-scoped `when@<env>` override. A bare root-level
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

        if (!str_starts_with($key, 'when@')) {
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
        if (\is_string($entry['path'] ?? null)) {
            return trim($entry['path']);
        }

        if (\is_string($entry['route'] ?? null)) {
            return \sprintf('route: %s', $entry['route']);
        }

        return null;
    }

    /**
     * @param array<string, mixed> $entry
     *
     * @return list<string>
     */
    private function requirementsOf(array $entry): array
    {
        $requirements = $this->stringListOf($entry['roles'] ?? $entry['role'] ?? null);

        if (\is_string($entry['allow_if'] ?? null)) {
            $requirements[] = \sprintf('allow_if: %s', $entry['allow_if']);
        }

        foreach (['methods' => '|', 'ips' => ', '] as $key => $separator) {
            $values = $this->stringListOf($entry[$key] ?? null);
            if ([] !== $values) {
                $requirements[] = \sprintf('%s: %s', $key, implode($separator, $values));
            }
        }

        if (\is_string($entry['requires_channel'] ?? null)) {
            $requirements[] = \sprintf('requires_channel: %s', $entry['requires_channel']);
        }

        return $requirements;
    }

    /**
     * @return list<string>
     */
    private function stringListOf(mixed $value): array
    {
        if (\is_string($value)) {
            $parts = array_map(trim(...), explode(',', $value));

            return array_values(array_filter($parts, static fn (string $part): bool => '' !== $part));
        }

        if (!\is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, is_string(...)));
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

        $map = [];
        foreach ($value as $key => $item) {
            $map[(string) $key] = $item;
        }

        return $map;
    }
}
